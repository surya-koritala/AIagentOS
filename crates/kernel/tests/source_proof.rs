#[path = "../source_proof.rs"]
mod source_proof;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture {
    _root: tempfile::TempDir,
    repository: PathBuf,
    context: PathBuf,
    commit: String,
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn prepare(repository: &Path, context: &Path) -> std::process::Output {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/prepare_source_context.py");
    Command::new(if cfg!(windows) { "python" } else { "python3" })
        .arg(script)
        .arg("--repository")
        .arg(repository)
        .arg("--output")
        .arg(context)
        .output()
        .unwrap()
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let repository = root.path().join("repo");
        let context = root.path().join("context");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init"]);
        fs::create_dir(repository.join("nested")).unwrap();
        fs::write(
            repository.join("nested/source.rs"),
            b"pub const MEASURED: u32 = 7;\n",
        )
        .unwrap();
        fs::write(repository.join(".gitignore"), ".env\ntarget/\n").unwrap();
        fs::write(repository.join("README.md"), "actual tracked source\n").unwrap();
        git(&repository, &["add", "."]);
        git(
            &repository,
            &[
                "-c",
                "user.name=Surya Koritala",
                "-c",
                "user.email=suryakoritala1324@gmail.com",
                "commit",
                "-s",
                "-m",
                "test: source proof fixture",
            ],
        );
        let commit = git(&repository, &["rev-parse", "HEAD"]);
        fs::write(
            repository.join(".env"),
            "TEST_ONLY_SECRET=must-not-enter-context\n",
        )
        .unwrap();
        let output = prepare(&repository, &context);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            _root: root,
            repository,
            context,
            commit,
        }
    }

    fn proof(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.context.join(source_proof::PROOF_FILE)).unwrap())
            .unwrap()
    }

    fn replace(&self, proof: &serde_json::Value) {
        fs::write(
            self.context.join(source_proof::PROOF_FILE),
            serde_json::to_vec(proof).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn actual_commit_tree_and_blobs_validate_without_git_or_credentials() {
    let fixture = Fixture::new();
    assert!(!fixture.context.join(".git").exists());
    assert!(!fixture.context.join(".env").exists());
    let verified = source_proof::verify_packaged_source(&fixture.context).unwrap();
    assert_eq!(verified.commit, fixture.commit);
    assert_eq!(verified.files.len(), 3);
    assert!(verified
        .directories
        .iter()
        .all(|path| !path.starts_with("target")));
}

#[test]
fn native_metrics_receipt_matches_the_actual_clean_git_checkout() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let commit = git(root, &["rev-parse", "HEAD"]);
    assert!(git(root, &["status", "--porcelain=v1", "--untracked-files=no"]).is_empty());
    let metrics = kernel::metrics::MetricsSnapshot::default().render_prometheus();
    assert!(metrics.contains("agentos_build_source_verified 1\n"));
    let mut parts = BTreeMap::new();
    for line in metrics
        .lines()
        .filter(|line| line.starts_with("agentos_build_source_sha1{"))
    {
        let (label, value) = line.rsplit_once(' ').unwrap();
        let part = label
            .split("part=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        parts.insert(part, value.parse::<u32>().unwrap());
    }
    assert_eq!(parts.len(), 5);
    let reconstructed: String = (0..5).map(|part| format!("{:08x}", parts[&part])).collect();
    assert_eq!(reconstructed, commit);
    if let Some(path) = std::env::var_os("AGENTOS_SOURCE_PROOF_NATIVE_RECEIPT_FILE") {
        fs::write(path, metrics).unwrap();
    }
}

#[test]
fn copied_commit_claim_and_modified_or_missing_file_never_validate() {
    let fixture = Fixture::new();
    let mut proof = fixture.proof();
    proof["commit"] = serde_json::json!("0000000000000000000000000000000000000001");
    fixture.replace(&proof);
    assert!(source_proof::verify_packaged_source(&fixture.context).is_err());
    proof["commit"] = serde_json::json!(fixture.commit);
    fixture.replace(&proof);
    fs::write(
        fixture.context.join("nested/source.rs"),
        "pub const MEASURED:u32=99;\n",
    )
    .unwrap();
    assert!(source_proof::verify_packaged_source(&fixture.context).is_err());
    fs::remove_file(fixture.context.join("nested/source.rs")).unwrap();
    assert!(source_proof::verify_packaged_source(&fixture.context).is_err());
}

#[test]
fn tampered_tree_missing_proof_and_unchecked_clean_flag_are_rejected() {
    let fixture = Fixture::new();
    let mut proof = fixture.proof();
    proof["clean"] = serde_json::json!(true);
    fixture.replace(&proof);
    assert!(source_proof::verify_packaged_source(&fixture.context).is_err());
    proof.as_object_mut().unwrap().remove("clean");
    let key = proof["trees"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    proof["trees"][key] = serde_json::json!("00");
    fixture.replace(&proof);
    assert!(source_proof::verify_packaged_source(&fixture.context).is_err());
    fs::remove_file(fixture.context.join(source_proof::PROOF_FILE)).unwrap();
    assert!(source_proof::verify_packaged_source(&fixture.context).is_err());
    fs::write(
        fixture.context.join(source_proof::PROOF_FILE),
        serde_json::to_vec(&serde_json::json!({"commit":fixture.commit,"clean":true})).unwrap(),
    )
    .unwrap();
    assert!(source_proof::verify_packaged_source(&fixture.context).is_err());
}

#[test]
fn proof_size_and_executable_mode_are_bounded_by_real_source() {
    let fixture = Fixture::new();
    let proof = fs::read(fixture.context.join(source_proof::PROOF_FILE)).unwrap();
    fs::write(
        fixture.context.join(source_proof::PROOF_FILE),
        vec![b'0'; 4 * 1024 * 1024 + 1],
    )
    .unwrap();
    assert!(source_proof::verify_packaged_source(&fixture.context).is_err());
    fs::write(fixture.context.join(source_proof::PROOF_FILE), proof).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            fixture.context.join("nested/source.rs"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(source_proof::verify_packaged_source(&fixture.context).is_err());
    }
}

#[test]
fn unattested_file_directory_or_git_metadata_are_rejected() {
    let fixture = Fixture::new();
    for name in ["extra.rs", ".env"] {
        fs::write(fixture.context.join(name), "unattested input").unwrap();
        assert!(source_proof::verify_packaged_source(&fixture.context).is_err());
        fs::remove_file(fixture.context.join(name)).unwrap();
    }
    for name in ["empty-extra", ".git"] {
        fs::create_dir(fixture.context.join(name)).unwrap();
        assert!(source_proof::verify_packaged_source(&fixture.context).is_err());
        fs::remove_dir(fixture.context.join(name)).unwrap();
    }
}

#[test]
fn dirty_checkout_cannot_generate_a_qualified_context() {
    let fixture = Fixture::new();
    fs::write(fixture.repository.join("README.md"), "dirty working copy\n").unwrap();
    let output = prepare(
        &fixture.repository,
        &fixture._root.path().join("dirty-context"),
    );
    assert!(!output.status.success());
    assert!(!fixture._root.path().join("dirty-context").exists());
}

#[test]
fn tracked_credential_path_is_refused_before_context_publication() {
    let fixture = Fixture::new();
    fs::write(
        fixture.repository.join("credentials.toml"),
        "fixture-only forbidden input\n",
    )
    .unwrap();
    git(&fixture.repository, &["add", "credentials.toml"]);
    git(
        &fixture.repository,
        &[
            "-c",
            "user.name=Surya Koritala",
            "-c",
            "user.email=suryakoritala1324@gmail.com",
            "commit",
            "-s",
            "-m",
            "test: forbidden credential path fixture",
        ],
    );
    let output = prepare(
        &fixture.repository,
        &fixture._root.path().join("credential-context"),
    );
    assert!(!output.status.success());
    assert!(!fixture._root.path().join("credential-context").exists());
}

#[test]
fn env_token_and_os_credential_paths_are_refused_case_insensitively() {
    for path in [
        ".ENV.production",
        "credentials.json",
        "api-key.txt",
        "TOKEN.json",
        ".AWS/config",
    ] {
        let fixture = Fixture::new();
        let credential = fixture.repository.join(path);
        fs::create_dir_all(credential.parent().unwrap()).unwrap();
        fs::write(&credential, "fixture-only forbidden material\n").unwrap();
        git(&fixture.repository, &["add", "-f", path]);
        git(
            &fixture.repository,
            &[
                "-c",
                "user.name=Surya Koritala",
                "-c",
                "user.email=suryakoritala1324@gmail.com",
                "commit",
                "-s",
                "-m",
                "test: sensitive source path fixture",
            ],
        );
        let output = prepare(
            &fixture.repository,
            &fixture._root.path().join("forbidden-context"),
        );
        assert!(!output.status.success());
        assert!(!fixture._root.path().join("forbidden-context").exists());
    }
}

#[cfg(unix)]
#[test]
fn symlink_replacement_does_not_validate_or_follow_external_source() {
    let fixture = Fixture::new();
    let path = fixture.context.join("nested/source.rs");
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(fixture.repository.join("nested/source.rs"), &path).unwrap();
    assert!(source_proof::verify_packaged_source(&fixture.context).is_err());
}

#[cfg(unix)]
#[test]
fn context_generator_refuses_output_alias_into_checkout() {
    let fixture = Fixture::new();
    let alias = fixture._root.path().join("output-alias");
    std::os::unix::fs::symlink(&fixture.repository, &alias).unwrap();
    let output = prepare(&fixture.repository, &alias.join("generated-context"));
    assert!(!output.status.success());
    assert!(!fixture.repository.join("generated-context").exists());
}
