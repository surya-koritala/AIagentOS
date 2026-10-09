//! Verify a packaged checkout against Git's commit/tree/blob object hashes.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
use serde::Deserialize;

pub const PROOF_FILE: &str = ".agentos-source-proof.json";
const MAX_PROOF_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_FILES: usize = 8192;
const MAX_TREES: usize = 2048;
const MAX_DEPTH: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceProof {
    version: u32,
    commit: String,
    commit_hex: String,
    trees: BTreeMap<String, String>,
}

fn hash_object(kind: &str, bytes: &[u8]) -> String {
    let mut digest = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    digest.update(format!("{kind} {}\0", bytes.len()).as_bytes());
    digest.update(bytes);
    hex(digest.finish().as_ref())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &str) -> Result<Vec<u8>, &'static str> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("source proof hex is not canonical");
    }
    value.as_bytes().chunks_exact(2).map(|pair| {
        let digit = |byte: u8| if byte <= b'9' { byte-b'0' } else { byte-b'a'+10 };
        Ok(digit(pair[0])*16+digit(pair[1]))
    }).collect()
}

fn component(name: &str) -> bool {
    let folded = name.to_ascii_lowercase();
    !name.is_empty() && name.len() <= 255 && name != "." && name != ".."
        && !name.chars().any(|character| matches!(character, '/' | '\\' | '\0' | '\n' | '\r'))
        && !matches!(folded.as_str(), ".git" | ".ssh" | ".aws" | ".azure" | ".gcloud" | ".kube" | ".docker" | ".config" | ".gnupg" | ".codex" | ".netrc" | ".git-credentials" | ".npmrc" | ".pypirc" | ".env" | "credentials" | "credentials.toml" | "credentials.json" | PROOF_FILE | "target" | "node_modules")
        && (!folded.starts_with(".env.") || folded == ".env.example")
        && !credential_file(&folded)
        && ![".pk8", ".p12", ".pfx", ".key"].iter().any(|suffix| folded.ends_with(*suffix))
}

fn credential_file(name: &str) -> bool {
    let normalized = name.replace('-', "_");
    let base = [".json", ".txt", ".toml", ".yaml", ".yml"]
        .iter().find_map(|extension| normalized.strip_suffix(*extension)).unwrap_or(&normalized);
    matches!(base, "api_key" | "api_keys" | "token" | "tokens" | "access_token" | "refresh_token")
}

pub struct VerifiedSource {
    pub commit: String,
    pub files: Vec<PathBuf>,
    pub directories: Vec<PathBuf>,
}

#[derive(Default)]
struct Inventory {
    files: BTreeSet<PathBuf>,
    directories: BTreeSet<PathBuf>,
    trees: BTreeSet<String>,
    total: u64,
}

/// Returns the object-authenticated commit only if all context bytes match.
/// Missing/invalid proof never yields a verified source identity.
pub fn verify_packaged_source(root: &Path) -> Result<VerifiedSource, &'static str> {
    let path = root.join(PROOF_FILE);
    let metadata = fs::symlink_metadata(&path).map_err(|_| "source proof is missing")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_PROOF_BYTES {
        return Err("source proof is not a bounded regular file");
    }
    let mut bytes = Vec::new();
    fs::File::open(path).map_err(|_| "source proof cannot be opened")?
        .take(MAX_PROOF_BYTES+1).read_to_end(&mut bytes).map_err(|_| "source proof cannot be read")?;
    if bytes.len() as u64 > MAX_PROOF_BYTES { return Err("source proof exceeds bound"); }
    let proof: SourceProof = serde_json::from_slice(&bytes).map_err(|_| "source proof is malformed")?;
    if proof.version != 1 || proof.commit.len() != 40 || proof.commit_hex.len() > 128*1024
        || proof.trees.is_empty() || proof.trees.len() > MAX_TREES {
        return Err("source proof identity or inventory is invalid");
    }
    let commit = unhex(&proof.commit_hex)?;
    if hash_object("commit", &commit) != proof.commit { return Err("source proof commit does not match its object"); }
    let header = commit.split(|byte| *byte == b'\n').next().ok_or("source commit has no tree")?;
    let tree = std::str::from_utf8(header).map_err(|_| "source commit tree header is invalid")?
        .strip_prefix("tree ").filter(|tree| tree.len()==40).ok_or("source commit tree header is invalid")?;
    let mut inventory = Inventory::default();
    walk_tree(root, Path::new(""), tree, &proof, &mut inventory, 0)?;
    if inventory.trees.len() != proof.trees.len() { return Err("source proof includes unreachable tree objects"); }
    check_extra_files(root, Path::new(""), &inventory, 0)?;
    Ok(VerifiedSource {
        commit: proof.commit,
        files: inventory.files.into_iter().collect(),
        directories: inventory.directories.into_iter().collect(),
    })
}

fn walk_tree(root: &Path, relative: &Path, tree: &str, proof: &SourceProof,
    inventory: &mut Inventory, depth: usize) -> Result<(), &'static str> {
    if depth > MAX_DEPTH { return Err("source tree exceeds depth bound"); }
    let body = unhex(proof.trees.get(tree).ok_or("source tree object is missing")?)?;
    if body.len() > 1024*1024 || hash_object("tree", &body) != tree { return Err("source tree object hash is invalid"); }
    inventory.trees.insert(tree.to_owned());
    let mut position = 0;
    let mut names = BTreeSet::new();
    while position < body.len() {
        let end = body[position..].iter().position(|byte| *byte==0).ok_or("source tree entry is malformed")?+position;
        let entry = std::str::from_utf8(&body[position..end]).map_err(|_| "source tree path is not UTF-8")?;
        let (mode,name) = entry.split_once(' ').ok_or("source tree entry has no mode")?;
        if !component(name) || !names.insert(name.to_owned()) { return Err("source tree path is unsafe or duplicated"); }
        position=end+1;
        let oid = body.get(position..position+20).ok_or("source tree entry has no object id")?;
        position+=20;
        let child = relative.join(name);
        if child == Path::new(PROOF_FILE) || child == Path::new("target") { return Err("source tree uses a reserved output path"); }
        let path = root.join(&child);
        let metadata = fs::symlink_metadata(&path).map_err(|_| "tracked source file is missing")?;
        if metadata.file_type().is_symlink() { return Err("packaged source rejects symlinks"); }
        if mode == "40000" {
            if !metadata.is_dir() { return Err("tracked source directory has wrong type"); }
            inventory.directories.insert(child.clone());
            walk_tree(root,&child,&hex(oid),proof,inventory,depth+1)?;
        } else if mode == "100644" || mode == "100755" {
            if !metadata.is_file() || inventory.files.len() == MAX_FILES || !inventory.files.insert(child) { return Err("source file type or inventory is invalid"); }
            inventory.total = inventory.total.checked_add(metadata.len()).filter(|value| *value <= MAX_SOURCE_BYTES).ok_or("source files exceed byte bound")?;
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                if (metadata.permissions().mode() & 0o111 != 0) != (mode == "100755") { return Err("source executable mode differs from Git"); }
            }
            let mut digest = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
            digest.update(format!("blob {}\0",metadata.len()).as_bytes());
            let mut source = fs::File::open(&path).map_err(|_| "source blob cannot be opened")?;
            let mut remaining = metadata.len();
            let mut buffer = [0_u8;64*1024];
            loop {
                let count = source.read(&mut buffer).map_err(|_| "source blob cannot be read")?;
                if count == 0 { break; }
                remaining = remaining.checked_sub(count as u64).ok_or("source blob changed while read")?;
                digest.update(&buffer[..count]);
            }
            if remaining != 0 || digest.finish().as_ref() != oid { return Err("source blob differs from Git object"); }
        } else { return Err("source proof rejects submodules or unsupported Git modes"); }
    }
    Ok(())
}

fn check_extra_files(root: &Path, relative: &Path, inventory: &Inventory, depth: usize) -> Result<(), &'static str> {
    if depth > MAX_DEPTH { return Err("source context exceeds depth bound"); }
    for entry in fs::read_dir(root.join(relative)).map_err(|_| "source context cannot be enumerated")? {
        let entry = entry.map_err(|_| "source context entry cannot be read")?;
        let child = relative.join(entry.file_name());
        let metadata = entry.file_type().map_err(|_| "source context type cannot be read")?;
        if child == Path::new(PROOF_FILE) { continue; }
        if child == Path::new("target") {
            if !metadata.is_dir() || metadata.is_symlink() { return Err("source build output path has unsafe type"); }
            continue;
        }
        if metadata.is_dir() {
            if !inventory.directories.contains(&child) { return Err("source context contains unattested directories"); }
            check_extra_files(root,&child,inventory,depth+1)?;
        }
        else if metadata.is_symlink() || !inventory.files.contains(&child) { return Err("source context contains unattested files"); }
    }
    Ok(())
}
