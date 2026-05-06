//! System Call Interface — the formal API between agents and kernel.
//!
//! Like Linux syscalls. Agents interact with the kernel ONLY through
//! numbered syscalls. This is the ABI contract.

use crate::agent_struct::AgentId;

/// System call numbers.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNum {
    // Agent management
    Create = 1,
    Clone = 2,
    Exit = 3,
    Wait = 4,
    Kill = 5,
    GetPid = 6,
    GetPPid = 7,

    // Tool operations
    ToolOpen = 10,
    ToolClose = 11,
    ToolRead = 12,
    ToolWrite = 13,
    ToolIoctl = 14,

    // Context operations
    CtxAlloc = 20,
    CtxFree = 21,
    CtxSnapshot = 22,
    CtxRestore = 23,

    // IPC
    Send = 30,
    Recv = 31,
    Subscribe = 32,
    Publish = 33,

    // Namespace
    Unshare = 40,
    SetNs = 41,

    // Scheduling
    Yield = 50,
    SetNice = 51,
    GetNice = 52,

    // Security
    GetCaps = 60,
    DropCap = 61,

    // System
    Uptime = 70,
    Info = 71,
    Shutdown = 72,
}

/// Syscall arguments (generic container).
#[derive(Debug, Clone)]
pub struct SyscallArgs {
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub str_arg: Option<String>,
    pub data: Option<Vec<u8>>,
}

impl SyscallArgs {
    pub fn none() -> Self {
        Self { arg0: 0, arg1: 0, arg2: 0, arg3: 0, str_arg: None, data: None }
    }
    pub fn with_u64(arg0: u64) -> Self {
        Self { arg0, arg1: 0, arg2: 0, arg3: 0, str_arg: None, data: None }
    }
    pub fn with_str(s: String) -> Self {
        Self { arg0: 0, arg1: 0, arg2: 0, arg3: 0, str_arg: Some(s), data: None }
    }
}

/// Syscall return value.
#[derive(Debug, Clone)]
pub enum SyscallResult {
    Ok(u64),
    OkStr(String),
    OkData(Vec<u8>),
    Err(SyscallError),
}

/// Syscall error codes (like errno).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    /// Permission denied.
    EPERM = -1,
    /// No such agent.
    ESRCH = -3,
    /// Bad tool descriptor.
    EBADF = -9,
    /// Out of memory/tokens.
    ENOMEM = -12,
    /// Permission denied (capabilities).
    EACCES = -13,
    /// Resource busy.
    EBUSY = -16,
    /// Invalid argument.
    EINVAL = -22,
    /// Too many open tools.
    EMFILE = -24,
    /// Function not implemented.
    ENOSYS = -38,
    /// Operation timed out.
    ETIMEDOUT = -110,
    /// Operation cancelled.
    ECANCELED = -125,
}

/// Syscall dispatch table.
pub struct SyscallTable {
    handlers: std::collections::HashMap<u32, Box<dyn Fn(AgentId, SyscallArgs) -> SyscallResult + Send + Sync>>,
}

impl SyscallTable {
    pub fn new() -> Self {
        Self { handlers: std::collections::HashMap::new() }
    }

    /// Register a syscall handler.
    pub fn register(&mut self, num: SyscallNum, handler: impl Fn(AgentId, SyscallArgs) -> SyscallResult + Send + Sync + 'static) {
        self.handlers.insert(num as u32, Box::new(handler));
    }

    /// Dispatch a syscall.
    pub fn dispatch(&self, caller: AgentId, num: SyscallNum, args: SyscallArgs) -> SyscallResult {
        match self.handlers.get(&(num as u32)) {
            Some(handler) => handler(caller, args),
            None => SyscallResult::Err(SyscallError::ENOSYS),
        }
    }

    /// Check if a syscall is registered.
    pub fn is_registered(&self, num: SyscallNum) -> bool {
        self.handlers.contains_key(&(num as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_registered_syscall() {
        let mut table = SyscallTable::new();
        table.register(SyscallNum::GetPid, |caller, _args| SyscallResult::Ok(caller));
        let result = table.dispatch(42, SyscallNum::GetPid, SyscallArgs::none());
        assert!(matches!(result, SyscallResult::Ok(42)));
    }

    #[test]
    fn unregistered_returns_enosys() {
        let table = SyscallTable::new();
        let result = table.dispatch(1, SyscallNum::Shutdown, SyscallArgs::none());
        assert!(matches!(result, SyscallResult::Err(SyscallError::ENOSYS)));
    }

    #[test]
    fn syscall_with_args() {
        let mut table = SyscallTable::new();
        table.register(SyscallNum::Kill, |_caller, args| {
            if args.arg0 == 0 { SyscallResult::Err(SyscallError::ESRCH) }
            else { SyscallResult::Ok(0) }
        });
        assert!(matches!(table.dispatch(1, SyscallNum::Kill, SyscallArgs::with_u64(0)), SyscallResult::Err(SyscallError::ESRCH)));
        assert!(matches!(table.dispatch(1, SyscallNum::Kill, SyscallArgs::with_u64(5)), SyscallResult::Ok(0)));
    }

    #[test]
    fn all_syscall_numbers_unique() {
        let nums = [
            SyscallNum::Create as u32, SyscallNum::Clone as u32, SyscallNum::Exit as u32,
            SyscallNum::Wait as u32, SyscallNum::Kill as u32, SyscallNum::GetPid as u32,
            SyscallNum::ToolOpen as u32, SyscallNum::ToolClose as u32, SyscallNum::ToolRead as u32,
            SyscallNum::Send as u32, SyscallNum::Recv as u32, SyscallNum::Yield as u32,
            SyscallNum::Shutdown as u32,
        ];
        let unique: std::collections::HashSet<u32> = nums.iter().cloned().collect();
        assert_eq!(unique.len(), nums.len());
    }

    #[test]
    fn error_codes_are_negative() {
        assert!((SyscallError::EPERM as i32) < 0);
        assert!((SyscallError::ENOMEM as i32) < 0);
        assert!((SyscallError::ENOSYS as i32) < 0);
    }
}
