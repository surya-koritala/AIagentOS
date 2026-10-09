//! Bind the compiled runtime to its actual tracked Git source.
//!
//! Missing Git metadata produces an unverified identity. Qualification must
//! refuse it; the runtime itself remains usable from a packaged source tree.

use std::path::{Path, PathBuf};
use std::process::Command;

fn git(root: &Path, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(arguments)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn main() {
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-changed=build.rs");
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root =
        git(&manifest, &["rev-parse", "--show-toplevel"]).map(|value| PathBuf::from(value.trim()));
    let mut commit = "0000000000000000000000000000000000000000".to_owned();
    let mut verified = false;
    if let Some(root) = root {
        if let Some(value) = git(&root, &["rev-parse", "HEAD"]) {
            let value = value.trim();
            if value.len() == 40
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                commit = value.to_owned();
                verified = git(&root, &["status", "--porcelain=v1", "--untracked-files=no"])
                    .is_some_and(|status| status.trim().is_empty());
            }
        }
        // Track source files, not ignored target artifacts. This also catches
        // dirty CLI/SDK changes without watching build output recursively.
        if let Some(files) = git(&root, &["ls-files", "-z"]) {
            for file in files.split('\0').filter(|file| !file.is_empty()) {
                println!("cargo:rerun-if-changed={}", root.join(file).display());
            }
        } else {
            verified = false;
        }
        for relative in ["HEAD", "logs/HEAD", "packed-refs"] {
            if let Some(path) = git(&root, &["rev-parse", "--git-path", relative]) {
                let path = root.join(path.trim());
                if path.exists() {
                    println!("cargo:rerun-if-changed={}", path.display());
                }
            }
        }
        if let Some(reference) = git(&root, &["symbolic-ref", "HEAD"]) {
            if let Some(path) = git(&root, &["rev-parse", "--git-path", reference.trim()]) {
                let path = root.join(path.trim());
                if path.exists() {
                    println!("cargo:rerun-if-changed={}", path.display());
                }
            }
        }
    }
    println!("cargo:rustc-env=AGENTOS_COMPILED_SOURCE_SHA={commit}");
    println!(
        "cargo:rustc-env=AGENTOS_COMPILED_SOURCE_VERIFIED={}",
        if verified { "1" } else { "0" }
    );
}
