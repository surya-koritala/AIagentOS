//! Owner-only Windows storage objects and write-through publication boundaries.
//!
//! Every private object is created with its descriptor already attached. Reads
//! validate the opened handle, not a second path lookup. Directory metadata
//! flush uses a writable directory handle and fails closed if unsupported.
//! CI process-crash evidence is not a physical power-loss qualification.

use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAceEx, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
    IsValidSid, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
    SetSecurityDescriptorOwner, TokenOwner, TokenUser, ACCESS_ALLOWED_ACE, ACL, ACL_REVISION,
    ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, TOKEN_OWNER, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileAttributeTagInfo, FlushFileBuffers,
    GetFileInformationByHandleEx, MoveFileExW, CREATE_NEW, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const MAX_TOKEN_BYTES: usize = 64 * 1024;

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct TestOpenProvenance {
    pub identity: (u32, u32, u32),
    pub access: u32,
    pub share: u32,
    pub file: &'static str,
    pub line: u32,
}

#[cfg(test)]
fn test_open_events() -> &'static std::sync::Mutex<std::collections::VecDeque<TestOpenProvenance>> {
    static EVENTS: std::sync::OnceLock<std::sync::Mutex<std::collections::VecDeque<TestOpenProvenance>>> = std::sync::OnceLock::new();
    EVENTS.get_or_init(|| std::sync::Mutex::new(std::collections::VecDeque::new()))
}

#[cfg(test)]
#[track_caller]
fn record_test_open(file: &File, access: u32, share: u32) {
    use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 { return; }
    let caller = std::panic::Location::caller();
    let mut events = test_open_events().lock().unwrap();
    if events.len() == 4096 { events.pop_front(); }
    events.push_back(TestOpenProvenance {
        identity: (info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow),
        access, share, file: caller.file(), line: caller.line(),
    });
}

#[cfg(test)]
pub(crate) fn test_open_provenance(identity: (u32, u32, u32)) -> Vec<TestOpenProvenance> {
    test_open_events().lock().unwrap().iter().filter(|event| event.identity == identity).cloned().collect()
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn bool_result(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn local_path(path: &Path) -> io::Result<Vec<u16>> {
    let absolute = std::path::absolute(path)?;
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {}
                _ => return Err(denied("private storage requires a local drive path")),
            },
            Component::ParentDir => return Err(denied("private storage rejects parent traversal")),
            Component::Normal(name) if name.encode_wide().any(|unit| unit == b':' as u16) => {
                return Err(denied("private storage rejects alternate data streams"));
            }
            _ => {}
        }
    }
    let mut wide: Vec<u16> = absolute.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(denied("private storage rejects NUL paths"));
    }
    wide.push(0);
    Ok(wide)
}

struct UserSid {
    user: Vec<usize>,
    default_owner: Vec<usize>,
}

impl UserSid {
    fn current() -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: OpenProcessToken writes one owned handle; OwnedHandle closes it.
        unsafe {
            bool_result(OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY,
                &mut token,
            ))?;
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let read = |class| -> io::Result<Vec<usize>> {
            let mut bytes = 0;
            // SAFETY: the zero-length query reports the required token buffer size.
            unsafe {
                GetTokenInformation(token.as_raw_handle(), class, null_mut(), 0, &mut bytes);
            }
            if bytes == 0 || bytes as usize > MAX_TOKEN_BYTES {
                return Err(denied("invalid current-user token size"));
            }
            let mut buffer = vec![0_usize; (bytes as usize).div_ceil(size_of::<usize>())];
            unsafe {
                bool_result(GetTokenInformation(
                    token.as_raw_handle(),
                    class,
                    buffer.as_mut_ptr().cast(),
                    bytes,
                    &mut bytes,
                ))?;
            }
            Ok(buffer)
        };
        Ok(Self {
            user: read(TokenUser)?,
            default_owner: read(TokenOwner)?,
        })
    }

    fn user(&self) -> PSID {
        // SAFETY: GetTokenInformation initialized an aligned TOKEN_USER buffer.
        unsafe { (*(self.user.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }

    fn default_owner(&self) -> PSID {
        // Exact OS-selected owner for this token, never an arbitrary group SID.
        unsafe { (*(self.default_owner.as_ptr().cast::<TOKEN_OWNER>())).Owner }
    }
}

struct PrivateDescriptor {
    user: UserSid,
    acl: Vec<usize>,
    descriptor: Box<SECURITY_DESCRIPTOR>,
}

impl PrivateDescriptor {
    fn new(directory: bool) -> io::Result<Self> {
        let user = UserSid::current()?;
        unsafe {
            bool_result(IsValidSid(user.user()))?;
        }
        let sid_bytes = unsafe { GetLengthSid(user.user()) } as usize;
        let acl_bytes =
            size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid_bytes;
        let mut acl = vec![0_usize; acl_bytes.div_ceil(size_of::<usize>())];
        let mut descriptor = Box::new(unsafe { zeroed::<SECURITY_DESCRIPTOR>() });
        let inheritance = if directory {
            CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
        } else {
            0
        };
        unsafe {
            bool_result(InitializeAcl(
                acl.as_mut_ptr().cast(),
                acl_bytes as u32,
                ACL_REVISION,
            ))?;
            bool_result(AddAccessAllowedAceEx(
                acl.as_mut_ptr().cast(),
                ACL_REVISION,
                inheritance,
                FILE_ALL_ACCESS,
                user.user(),
            ))?;
            let security = (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast();
            bool_result(InitializeSecurityDescriptor(security, 1))?;
            bool_result(SetSecurityDescriptorOwner(security, user.user(), 0))?;
            bool_result(SetSecurityDescriptorDacl(
                security,
                1,
                acl.as_ptr().cast(),
                0,
            ))?;
            bool_result(SetSecurityDescriptorControl(
                security,
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            ))?;
        }
        Ok(Self {
            user,
            acl,
            descriptor,
        })
    }

    fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&mut *self.descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            bInheritHandle: 0,
        }
    }
}

struct SecurityInfo(PSECURITY_DESCRIPTOR);
impl Drop for SecurityInfo {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn attributes(file: &File) -> io::Result<u32> {
    let mut info = unsafe { zeroed::<FILE_ATTRIBUTE_TAG_INFO>() };
    unsafe {
        bool_result(GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        ))?;
    }
    if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(denied("private storage rejects reparse points"));
    }
    Ok(info.FileAttributes)
}

fn reject_reparse_ancestors(path: &Path) -> io::Result<()> {
    let absolute = std::path::absolute(path)?;
    for parent in absolute.ancestors().skip(1) {
        let wide = local_path(parent)?;
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_handle(raw) };
        if attributes(&file)? & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(denied("private storage parent is not a regular directory"));
        }
    }
    Ok(())
}

#[cfg_attr(test, track_caller)]
fn open(path: &Path, directory: bool, access: u32) -> io::Result<File> {
    reject_reparse_ancestors(path)?;
    let wide = local_path(path)?;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(raw) };
    let actual = attributes(&file)? & FILE_ATTRIBUTE_DIRECTORY != 0;
    if actual != directory {
        return Err(denied("private storage object has the wrong type"));
    }
    #[cfg(test)]
    record_test_open(&file, access | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    Ok(file)
}

fn owner_and_acl(file: &File, user: &UserSid, strict: bool) -> io::Result<()> {
    attributes(file)?;
    let mut owner = null_mut();
    let mut acl = null_mut();
    let mut descriptor = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let _descriptor = SecurityInfo(descriptor);
    let owner_matches = unsafe {
        IsValidSid(owner) != 0
            && (EqualSid(owner, user.user()) != 0 || EqualSid(owner, user.default_owner()) != 0)
    };
    if !owner_matches {
        return Err(denied(
            "private storage is not owned by the current process user",
        ));
    }
    if !strict {
        return Ok(());
    }
    let mut control = 0;
    let mut revision = 0;
    unsafe {
        bool_result(GetSecurityDescriptorControl(
            descriptor,
            &mut control,
            &mut revision,
        ))?;
    }
    if acl.is_null() || control & SE_DACL_PROTECTED == 0 {
        return Err(denied("private storage requires a protected non-null DACL"));
    }
    let mut size = unsafe { zeroed::<ACL_SIZE_INFORMATION>() };
    unsafe {
        bool_result(GetAclInformation(
            acl,
            (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ))?;
    }
    if size.AceCount != 1 {
        return Err(denied("private storage requires exactly one owner ACE"));
    }
    let mut ace: *mut c_void = null_mut();
    unsafe {
        bool_result(GetAce(acl, 0, &mut ace))?;
    }
    let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
    let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
    // ACCESS_ALLOWED_ACE_TYPE is zero in the Win32 ACL wire structure.
    if allowed.Header.AceType != 0
        || allowed.Header.AceFlags & 0x10 != 0
        || allowed.Mask != FILE_ALL_ACCESS
        || unsafe { IsValidSid(sid) == 0 || EqualSid(sid, user.user()) == 0 }
    {
        return Err(denied(
            "private storage DACL grants access beyond its current owner",
        ));
    }
    Ok(())
}

/// Validate the opened object before any key or manifest bytes are read.
pub(crate) fn open_read(path: &Path, owner_only: bool) -> io::Result<File> {
    let file = open(path, false, FILE_GENERIC_READ | READ_CONTROL)?;
    if owner_only {
        owner_and_acl(&file, &UserSid::current()?, true)?;
    }
    Ok(file)
}

pub(crate) fn verify_file(file: &File, directory: bool) -> io::Result<()> {
    if (attributes(file)? & FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
        return Err(denied("private storage object has the wrong type"));
    }
    owner_and_acl(file, &UserSid::current()?, true)
}

pub(crate) fn verify_path(path: &Path, directory: bool) -> io::Result<()> {
    verify_file(&open(path, directory, READ_CONTROL)?, directory)
}

pub(crate) fn check_directory(path: &Path) -> io::Result<()> {
    drop(open(path, true, FILE_READ_ATTRIBUTES)?);
    Ok(())
}

pub(crate) fn protect_path(path: &Path, directory: bool) -> io::Result<()> {
    let file = open(path, directory, READ_CONTROL | WRITE_DAC)?;
    let descriptor = PrivateDescriptor::new(directory)?;
    // A permissive object owned by the exact current TokenUser/TokenOwner may
    // be narrowed. The object owner stays unchanged; foreign owners are rejected.
    owner_and_acl(&file, &descriptor.user, false)?;
    let result = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            descriptor.acl.as_ptr().cast(),
            null(),
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    verify_file(&file, directory)
}

pub(crate) fn create_new_file(path: &Path) -> io::Result<File> {
    reject_reparse_ancestors(path)?;
    let wide = local_path(path)?;
    let mut descriptor = PrivateDescriptor::new(false)?;
    let security = descriptor.attributes();
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &security,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(raw) };
    verify_file(&file, false)?;
    Ok(file)
}

pub(crate) fn open_private_rw(path: &Path) -> io::Result<File> {
    match create_new_file(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            protect_path(path, false)?;
            let file = open(
                path,
                false,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL,
            )?;
            verify_file(&file, false)?;
            Ok(file)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn create_directory(path: &Path) -> io::Result<()> {
    reject_reparse_ancestors(path)?;
    let wide = local_path(path)?;
    let mut descriptor = PrivateDescriptor::new(true)?;
    let security = descriptor.attributes();
    unsafe {
        bool_result(CreateDirectoryW(wide.as_ptr(), &security))?;
    }
    verify_path(path, true)
}

pub(crate) fn ensure_directory(path: &Path) -> io::Result<()> {
    match create_directory(path) {
        Ok(()) => Ok(()),
        Err(error) if matches!(error.raw_os_error(), Some(code) if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32) => {
            protect_path(path, true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| denied("private directory has no parent"))?;
            ensure_directory(parent)?;
            create_directory(path)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn durable_rename(source: &Path, destination: &Path) -> io::Result<()> {
    reject_reparse_ancestors(destination)?;
    let directory = std::fs::symlink_metadata(source)?.is_dir();
    let source_handle = open(source, directory, READ_CONTROL)?;
    owner_and_acl(&source_handle, &UserSid::current()?, false)?;
    drop(source_handle);
    if let Ok(metadata) = std::fs::symlink_metadata(destination) {
        let destination_handle = open(destination, metadata.is_dir(), READ_CONTROL)?;
        owner_and_acl(&destination_handle, &UserSid::current()?, false)?;
        drop(destination_handle);
    }
    let source = local_path(source)?;
    let destination = local_path(destination)?;
    // No COPY_ALLOWED: cross-volume publication must fail rather than silently
    // becoming a non-atomic copy/delete operation.
    unsafe {
        bool_result(MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING,
        ))
    }
}

#[derive(Debug)]
enum DirectorySyncMechanism {
    DirectoryHandleFlush,
}

/// Flush the actual directory handle; unsupported filesystems fail closed.
pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    sync_directory_with_evidence(path).map(|_| ())
}

fn sync_directory_with_evidence(path: &Path) -> io::Result<DirectorySyncMechanism> {
    let directory = open(path, true, FILE_GENERIC_WRITE | READ_CONTROL)?;
    if unsafe { FlushFileBuffers(directory.as_raw_handle()) } != 0 {
        return Ok(DirectorySyncMechanism::DirectoryHandleFlush);
    }
    Err(io::Error::last_os_error())
}

pub(crate) fn write_config(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure_directory(parent)?;
    if path.try_exists()? {
        protect_path(path, false)?;
    }
    let stage: PathBuf = parent.join(format!(".agentos-config-{}.stage", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut output = create_new_file(&stage)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        drop(output);
        durable_rename(&stage, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&stage);
    }
    result
}

pub(crate) fn copy_private(source: &Path, destination: &Path) -> io::Result<u64> {
    let mut source = open_read(source, false)?;
    let mut destination = create_new_file(destination)?;
    let count = io::copy(&mut source, &mut destination)?;
    destination.sync_all()?;
    Ok(count)
}

/// Stable local operator identity, derived only from the current TokenUser SID.
pub(crate) fn operator_identity() -> io::Result<String> {
    let user = UserSid::current()?;
    let sid = user.user();
    unsafe {
        bool_result(IsValidSid(sid))?;
    }
    let size = unsafe { GetLengthSid(sid) } as usize;
    if size == 0 || size > 68 {
        return Err(denied("invalid operator SID length"));
    }
    let bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), size) };
    let identity = ring::digest::digest(&ring::digest::SHA256, bytes);
    Ok(format!(
        "windows-user:{}",
        identity
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

#[cfg(test)]
pub(crate) fn grant_world_read_for_test(path: &Path, directory: bool) {
    use std::mem::size_of_val;
    use windows_sys::Win32::Security::{CreateWellKnownSid, WinWorldSid};
    let file = open(path, directory, READ_CONTROL | WRITE_DAC).unwrap();
    let user = UserSid::current().unwrap();
    let mut world = [0_usize; 16];
    let mut world_bytes = size_of_val(&world) as u32;
    let mut acl = [0_usize; 64];
    let inheritance = if directory {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        0
    };
    unsafe {
        assert_ne!(
            CreateWellKnownSid(
                WinWorldSid,
                null_mut(),
                world.as_mut_ptr().cast(),
                &mut world_bytes
            ),
            0
        );
        assert_ne!(
            InitializeAcl(
                acl.as_mut_ptr().cast(),
                size_of_val(&acl) as u32,
                ACL_REVISION
            ),
            0
        );
        assert_ne!(
            AddAccessAllowedAceEx(
                acl.as_mut_ptr().cast(),
                ACL_REVISION,
                inheritance,
                FILE_ALL_ACCESS,
                user.user()
            ),
            0
        );
        assert_ne!(
            AddAccessAllowedAceEx(
                acl.as_mut_ptr().cast(),
                ACL_REVISION,
                inheritance,
                FILE_GENERIC_READ,
                world.as_mut_ptr().cast()
            ),
            0
        );
        assert_eq!(
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl.as_ptr().cast(),
                null()
            ),
            0
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn private_root() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        protect_path(directory.path(), true).unwrap();
        directory
    }

    struct NativeTestUser {
        name: Vec<u16>,
        sid: Vec<usize>,
    }

    impl NativeTestUser {
        fn create() -> Self {
            use windows_sys::Win32::NetworkManagement::NetManagement::{
                NetApiBufferFree, NetUserAdd, NetUserGetInfo, UF_NORMAL_ACCOUNT, UF_SCRIPT,
                USER_INFO_1, USER_INFO_23, USER_PRIV_USER,
            };
            let mut name: Vec<u16> =
                format!("aofs_{}\0", &uuid::Uuid::new_v4().simple().to_string()[..8])
                    .encode_utf16()
                    .collect();
            let mut password: Vec<u16> = format!("Aa7!{}\0", uuid::Uuid::new_v4().simple())
                .encode_utf16()
                .collect();
            let info = USER_INFO_1 {
                usri1_name: name.as_mut_ptr(),
                usri1_password: password.as_mut_ptr(),
                usri1_priv: USER_PRIV_USER,
                usri1_flags: UF_NORMAL_ACCOUNT | UF_SCRIPT,
                ..Default::default()
            };
            let mut parameter = 0;
            let result = unsafe {
                NetUserAdd(
                    null(),
                    1,
                    (&info as *const USER_INFO_1).cast(),
                    &mut parameter,
                )
            };
            password.fill(0);
            assert_eq!(
                result, 0,
                "disposable Windows user fixture creation failed at parameter {parameter}"
            );
            let mut user = Self {
                name,
                sid: Vec::new(),
            };
            let mut buffer = null_mut();
            unsafe {
                assert_eq!(
                    NetUserGetInfo(null(), user.name.as_ptr(), 23, &mut buffer),
                    0
                );
                let sid = (*(buffer.cast::<USER_INFO_23>())).usri23_user_sid;
                assert_ne!(IsValidSid(sid), 0);
                let bytes = GetLengthSid(sid) as usize;
                user.sid = vec![0_usize; bytes.div_ceil(size_of::<usize>())];
                std::ptr::copy_nonoverlapping(
                    sid.cast::<u8>(),
                    user.sid.as_mut_ptr().cast::<u8>(),
                    bytes,
                );
                assert_eq!(NetApiBufferFree(buffer.cast()), 0);
            }
            user
        }
        fn sid(&self) -> PSID {
            self.sid.as_ptr().cast_mut().cast()
        }
    }

    impl Drop for NativeTestUser {
        fn drop(&mut self) {
            // The account exists only in a disposable hosted CI test process.
            unsafe {
                windows_sys::Win32::NetworkManagement::NetManagement::NetUserDel(
                    null(),
                    self.name.as_ptr(),
                );
            }
        }
    }

    #[test]
    fn windows_private_file_is_protected_at_birth_and_never_overwrites() {
        let root = private_root();
        assert_eq!(operator_identity().unwrap(), operator_identity().unwrap());
        grant_world_read_for_test(root.path(), true);
        let path = root.path().join("private-key.json");
        let mut file = create_new_file(&path).unwrap();
        // Read the security descriptor of the handle immediately after CREATE_NEW,
        // before any content write or later permission adjustment.
        verify_file(&file, false).unwrap();
        let mut owner = null_mut();
        let mut descriptor = null_mut();
        unsafe {
            assert_eq!(
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    &mut owner,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut descriptor
                ),
                0
            );
            assert_ne!(
                EqualSid(owner, UserSid::current().unwrap().user()),
                0,
                "new private objects must explicitly use TokenUser, not a default owner group"
            );
            LocalFree(descriptor);
        }
        file.write_all(b"private fixture bytes").unwrap();
        file.sync_all().unwrap();
        assert!(create_new_file(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"private fixture bytes");
    }

    #[test]
    fn windows_private_directory_does_not_inherit_world_access() {
        let root = private_root();
        grant_world_read_for_test(root.path(), true);
        let child = root.path().join("child");
        create_directory(&child).unwrap();
        verify_path(&child, true).unwrap();
        let key = child.join("key");
        drop(create_new_file(&key).unwrap());
        verify_path(&key, false).unwrap();
    }

    #[test]
    fn windows_private_key_load_rejects_another_trustee() {
        let root = private_root();
        let key = root.path().join("key.json");
        crate::storage_encryption::generate_storage_encryption_key_file(
            "windows-private-fixture",
            &key,
        )
        .unwrap();
        crate::storage_encryption::load_storage_encryption_key(&key).unwrap();
        grant_world_read_for_test(&key, false);
        assert!(crate::storage_encryption::load_storage_encryption_key(&key).is_err());
    }

    #[test]
    fn windows_private_reparse_files_and_ancestors_are_rejected() {
        let root = private_root();
        let source = root.path().join("source");
        let mut file = create_new_file(&source).unwrap();
        file.write_all(b"unchanged").unwrap();
        drop(file);
        let linked = root.path().join("linked");
        std::os::windows::fs::symlink_file(&source, &linked).unwrap();
        assert!(open_read(&linked, false).is_err());
        assert!(open_private_rw(&linked).is_err());
        assert!(write_config(&linked, b"must not replace a reparse object").is_err());
        let linked_directory = root.path().join("linked-dir");
        std::os::windows::fs::symlink_dir(root.path(), &linked_directory).unwrap();
        assert!(open_read(&linked_directory.join("source"), false).is_err());
        assert!(create_new_file(&linked_directory.join("injected")).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"unchanged");
    }

    #[test]
    fn windows_private_config_replacement_repairs_acl_and_cleans_stage() {
        let root = private_root();
        let path = root.path().join("config.toml");
        write_config(&path, b"first").unwrap();
        grant_world_read_for_test(&path, false);
        write_config(&path, b"second").unwrap();
        verify_path(&path, false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn windows_private_database_and_signed_backup_round_trip() {
        let root = private_root();
        let database = root.path().join("database.sqlite3");
        let manager = crate::context::SqliteContextManager::new(&database).unwrap();
        verify_path(&database, false).unwrap();
        let backups = root.path().join("backups");
        let (signer, _) =
            crate::storage::BackupSigningKey::generate("windows-native-fixture").unwrap();
        manager
            .create_signed_backup(&backups, "native-private-fixture", &signer)
            .unwrap();
        verify_path(&backups, true).unwrap();
        verify_path(&backups.join("native-private-fixture"), true).unwrap();
        let manifest = backups.join("native-private-fixture/manifest.json");
        verify_path(&manifest, false).unwrap();
        let link = backups.join("linked-manifest.json");
        std::os::windows::fs::symlink_file(&manifest, &link).unwrap();
        assert!(open_read(&link, false).is_err());
    }

    #[test]
    fn windows_private_write_through_rename_preserves_acl_and_content() {
        let root = private_root();
        let source = root.path().join("source");
        let destination = root.path().join("published");
        let mut output = create_new_file(&source).unwrap();
        output.write_all(b"durable-content").unwrap();
        output.sync_all().unwrap();
        drop(output);
        durable_rename(&source, &destination).unwrap();
        let mechanism = sync_directory_with_evidence(root.path()).unwrap();
        println!("native_directory_sync_mechanism={mechanism:?}");
        verify_path(&destination, false).unwrap();
        let mut bytes = String::new();
        open_read(&destination, true)
            .unwrap()
            .read_to_string(&mut bytes)
            .unwrap();
        assert_eq!(bytes, "durable-content");
        assert!(!source.exists());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn windows_private_directory_sync_rejects_files_and_reparse_points() {
        let root = private_root();
        let file = root.path().join("file");
        drop(create_new_file(&file).unwrap());
        assert!(sync_directory(&file).is_err());
        let linked = root.path().join("directory-link");
        std::os::windows::fs::symlink_dir(root.path(), &linked).unwrap();
        assert!(sync_directory(&linked).is_err());
    }

    #[test]
    fn windows_private_foreign_owner_is_rejected_before_acl_repair() {
        use windows_sys::Win32::Storage::FileSystem::WRITE_OWNER;
        const CHILD: &str = "AIAGENTOS_WINDOWS_FOREIGN_OWNER_TEST";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "windows_private_fs::tests::windows_private_foreign_owner_is_rejected_before_acl_repair", "--nocapture"])
                .env(CHILD, "1").status().unwrap();
            assert!(status.success(), "isolated native ownership test failed");
            return;
        }
        // SeRestorePrivilege is enabled only in this disposable test process.
        // Production never requests it or changes the owner of a foreign object.
        use windows_sys::Win32::Foundation::{GetLastError, LUID};
        use windows_sys::Win32::Security::{
            AdjustTokenPrivileges, CreateWellKnownSid, LookupPrivilegeValueW, WinLocalSystemSid,
            LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        };
        let mut token = null_mut();
        let mut luid = unsafe { zeroed::<LUID>() };
        let privilege: Vec<u16> = "SeRestorePrivilege\0".encode_utf16().collect();
        unsafe {
            assert_ne!(
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                    &mut token
                ),
                0
            );
            assert_ne!(
                LookupPrivilegeValueW(null(), privilege.as_ptr(), &mut luid),
                0
            );
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        unsafe {
            assert_ne!(
                AdjustTokenPrivileges(
                    token.as_raw_handle(),
                    0,
                    &privileges,
                    0,
                    null_mut(),
                    null_mut()
                ),
                0
            );
            assert_ne!(
                GetLastError(),
                1300,
                "hosted Windows ownership fixture requires SeRestorePrivilege"
            );
        }
        let root = private_root();
        let path = root.path().join("foreign-key.json");
        crate::storage_encryption::generate_storage_encryption_key_file(
            "foreign-owner-fixture",
            &path,
        )
        .unwrap();
        let mut system = [0_usize; 16];
        let mut bytes = std::mem::size_of_val(&system) as u32;
        let file = open(&path, false, READ_CONTROL | WRITE_OWNER).unwrap();
        unsafe {
            assert_ne!(
                CreateWellKnownSid(
                    WinLocalSystemSid,
                    null_mut(),
                    system.as_mut_ptr().cast(),
                    &mut bytes
                ),
                0
            );
            assert_eq!(
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    system.as_mut_ptr().cast(),
                    null_mut(),
                    null(),
                    null()
                ),
                0
            );
        }
        assert!(crate::storage_encryption::load_storage_encryption_key(&path).is_err());
        assert!(protect_path(&path, false).is_err());
        // Preserve the exact foreign owner until the explicit test cleanup.
        let mut owner = null_mut();
        let mut descriptor = null_mut();
        unsafe {
            assert_eq!(
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    &mut owner,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut descriptor
                ),
                0
            );
            assert_ne!(EqualSid(owner, system.as_mut_ptr().cast()), 0);
            LocalFree(descriptor);
            assert_eq!(
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    UserSid::current().unwrap().user(),
                    null_mut(),
                    null(),
                    null()
                ),
                0
            );
        }
        let other_user = NativeTestUser::create();
        unsafe {
            assert_eq!(
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    other_user.sid(),
                    null_mut(),
                    null(),
                    null()
                ),
                0
            );
        }
        assert!(crate::storage_encryption::load_storage_encryption_key(&path).is_err());
        assert!(protect_path(&path, false).is_err());
        let mut actual_owner = null_mut();
        let mut actual_descriptor = null_mut();
        unsafe {
            assert_eq!(
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    &mut actual_owner,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut actual_descriptor
                ),
                0
            );
            assert_ne!(
                EqualSid(actual_owner, other_user.sid()),
                0,
                "rejected protection must preserve the foreign user's ownership"
            );
            LocalFree(actual_descriptor);
            assert_eq!(
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    UserSid::current().unwrap().user(),
                    null_mut(),
                    null(),
                    null()
                ),
                0
            );
        }
    }

    #[test]
    fn windows_private_publication_survives_process_exit() {
        const ROOT: &str = "AIAGENTOS_WINDOWS_PUBLICATION_CRASH_TEST";
        if let Some(root) = std::env::var_os(ROOT) {
            let root = PathBuf::from(root);
            let stage = root.join("stage");
            create_directory(&stage).unwrap();
            let mut data = create_new_file(&stage.join("state")).unwrap();
            data.write_all(b"committed-state").unwrap();
            data.sync_all().unwrap();
            drop(data);
            sync_directory(&stage).unwrap();
            durable_rename(&stage, &root.join("published")).unwrap();
            sync_directory(&root).unwrap();
            std::process::exit(86);
        }
        let root = private_root();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows_private_fs::tests::windows_private_publication_survives_process_exit",
                "--nocapture",
            ])
            .env(ROOT, root.path())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86));
        let published = root.path().join("published");
        verify_path(&published, true).unwrap();
        verify_path(&published.join("state"), false).unwrap();
        assert_eq!(
            std::fs::read(published.join("state")).unwrap(),
            b"committed-state"
        );
        assert!(!root.path().join("stage").exists());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }
}
