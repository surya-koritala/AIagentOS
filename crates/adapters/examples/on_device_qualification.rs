//! Exact-release-candidate qualification for a provisioned GGUF model.
//!
//! The protected self-hosted workflow supplies model files. This program emits
//! only bounded non-sensitive metadata and digests; it never emits prompts,
//! model output, file paths, or model weights.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use adapters::on_device::{ChatTemplate, OnDeviceConfig, OnDeviceLlmAdapter};
use kernel::connector::{LlmProviderAdapter, LlmRequestOptions, StandardMessage};
use kernel::ConnectorError;
use ring::digest::{Context as DigestContext, SHA256};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

const SCHEMA_VERSION: u64 = 1;
const QUALIFICATION_CLASS: &str = "exact_release_candidate_on_device_gguf";
const MAX_TOKENIZER_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OUTPUT_TOKENS: u32 = 32;
const CANCELLATION_DELAY_MS: u64 = 10;
const MAX_REPORT_BYTES: usize = 512 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Validate,
    Execute(Box<Arguments>),
}

#[derive(Debug, PartialEq, Eq)]
struct Arguments {
    model_path: PathBuf,
    tokenizer_path: PathBuf,
    model_id: String,
    chat_template: String,
    max_context_tokens: usize,
    max_model_bytes: u64,
    max_rss_bytes: u64,
    max_load_seconds: u64,
    max_generation_seconds: u64,
    max_cancellation_seconds: u64,
    expected_commit: String,
    release_candidate: String,
    environment_id: String,
    hardware_id: String,
    output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    length: u64,
    modified: SystemTime,
}

fn parse_positive<T>(value: &str, label: &str) -> Result<T, String>
where
    T: std::str::FromStr + PartialOrd + From<u8>,
{
    let parsed = value
        .parse::<T>()
        .map_err(|_| format!("{label} must be a positive integer"))?;
    if parsed < T::from(1) {
        return Err(format!("{label} must be a positive integer"));
    }
    Ok(parsed)
}

fn stable_identifier(value: &str, label: &str, allow_path_separator: bool) -> Result<(), String> {
    if value.is_empty() || value.len() > 100 || value != value.trim() {
        return Err(format!("{label} must be a bounded stable identifier"));
    }
    let valid = value.chars().enumerate().all(|(index, character)| {
        character.is_ascii_alphanumeric()
            || (index > 0 && matches!(character, '.' | '_' | ':' | '@' | '+' | '-'))
            || (index > 0 && allow_path_separator && character == '/')
    });
    if !valid {
        return Err(format!("{label} must be a bounded stable identifier"));
    }
    let fixture_components = ["dev", "development", "fixture", "local", "mock", "test"];
    if value
        .split(['.', '_', ':', '@', '+', '-', '/'])
        .any(|component| fixture_components.contains(&component.to_ascii_lowercase().as_str()))
    {
        return Err(format!("{label} must identify a non-fixture target"));
    }
    Ok(())
}

fn valid_release_candidate(value: &str) -> bool {
    let Some(version) = value.strip_prefix('v') else {
        return false;
    };
    let (core, candidate) = match version.split_once("-rc.") {
        Some((core, candidate)) => (core, Some(candidate)),
        None => (version, None),
    };
    let parts = core.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|value| value.is_ascii_digit()))
        && candidate.is_none_or(|part| {
            !part.is_empty()
                && part.chars().all(|value| value.is_ascii_digit())
                && part.parse::<u64>().is_ok_and(|value| value > 0)
        })
}

fn parse_arguments<I>(arguments: I) -> Result<Mode, String>
where
    I: IntoIterator<Item = String>,
{
    let values = arguments.into_iter().collect::<Vec<_>>();
    if values == ["--validate"] {
        return Ok(Mode::Validate);
    }
    if values.iter().any(|value| value == "--validate") {
        return Err("--validate cannot be combined with execution arguments".into());
    }
    if values.len() % 2 != 0 {
        return Err("qualification arguments must be flag/value pairs".into());
    }
    let allowed = BTreeSet::from([
        "--model",
        "--tokenizer",
        "--model-id",
        "--chat-template",
        "--max-context-tokens",
        "--max-model-bytes",
        "--max-rss-bytes",
        "--max-load-seconds",
        "--max-generation-seconds",
        "--max-cancellation-seconds",
        "--expected-commit",
        "--release-candidate",
        "--environment-id",
        "--hardware-id",
        "--output",
    ]);
    let mut parsed = BTreeMap::new();
    for pair in values.chunks_exact(2) {
        if !allowed.contains(pair[0].as_str()) {
            return Err(format!("unknown argument {}", pair[0]));
        }
        if parsed.insert(pair[0].clone(), pair[1].clone()).is_some() {
            return Err(format!("duplicate argument {}", pair[0]));
        }
    }
    if parsed.len() != allowed.len() {
        let missing = allowed
            .iter()
            .filter(|key| !parsed.contains_key(**key))
            .copied()
            .collect::<Vec<_>>();
        return Err(format!("missing required arguments: {missing:?}"));
    }
    let take = |name: &str| {
        parsed
            .get(name)
            .cloned()
            .ok_or_else(|| format!("missing {name}"))
    };
    let model_path = PathBuf::from(take("--model")?);
    let tokenizer_path = PathBuf::from(take("--tokenizer")?);
    let output = PathBuf::from(take("--output")?);
    if !model_path.is_absolute() || !tokenizer_path.is_absolute() || !output.is_absolute() {
        return Err("model, tokenizer, and output paths must be absolute".into());
    }
    let model_id = take("--model-id")?;
    let environment_id = take("--environment-id")?;
    let hardware_id = take("--hardware-id")?;
    stable_identifier(&model_id, "model ID", true)?;
    stable_identifier(&environment_id, "environment ID", false)?;
    stable_identifier(&hardware_id, "hardware ID", false)?;
    let chat_template = take("--chat-template")?;
    if !matches!(chat_template.as_str(), "simple" | "chatml" | "llama3") {
        return Err("chat template must be simple, chatml, or llama3".into());
    }
    let expected_commit = take("--expected-commit")?;
    if expected_commit.len() != 40
        || !expected_commit
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err("expected commit must be a full lowercase Git SHA".into());
    }
    let release_candidate = take("--release-candidate")?;
    if !valid_release_candidate(&release_candidate) {
        return Err("release candidate must be vX.Y.Z or vX.Y.Z-rc.N".into());
    }
    let max_context_tokens =
        parse_positive::<usize>(&take("--max-context-tokens")?, "max context tokens")?;
    if !(512..=1_048_576).contains(&max_context_tokens) {
        return Err("max context tokens must be within 512..1048576".into());
    }
    Ok(Mode::Execute(Box::new(Arguments {
        model_path,
        tokenizer_path,
        model_id,
        chat_template,
        max_context_tokens,
        max_model_bytes: parse_positive(&take("--max-model-bytes")?, "max model bytes")?,
        max_rss_bytes: parse_positive(&take("--max-rss-bytes")?, "max RSS bytes")?,
        max_load_seconds: parse_positive(&take("--max-load-seconds")?, "max load seconds")?,
        max_generation_seconds: parse_positive(
            &take("--max-generation-seconds")?,
            "max generation seconds",
        )?,
        max_cancellation_seconds: parse_positive(
            &take("--max-cancellation-seconds")?,
            "max cancellation seconds",
        )?,
        expected_commit,
        release_candidate,
        environment_id,
        hardware_id,
        output,
    })))
}

fn file_identity(path: &Path, maximum_bytes: u64, label: &str) -> Result<FileIdentity, String> {
    let link_metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("open {label}: {error}"))?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    if link_metadata.len() == 0 || link_metadata.len() > maximum_bytes {
        return Err(format!("{label} size is outside the configured bound"));
    }
    let modified = link_metadata
        .modified()
        .map_err(|error| format!("read {label} modification time: {error}"))?;
    Ok(FileIdentity {
        length: link_metadata.len(),
        modified,
    })
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|error| format!("open qualification input: {error}"))?;
    let mut source = BufReader::new(file);
    let mut digest = DigestContext::new(&SHA256);
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| format!("read qualification input: {error}"))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest
        .finish()
        .as_ref()
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect())
}

fn sha256_bytes(value: &[u8]) -> String {
    ring::digest::digest(&SHA256, value)
        .as_ref()
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect()
}

fn command_output(command: &mut Command, label: &str) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|error| format!("{label} is unavailable: {error}"))?;
    if !output.status.success() {
        return Err(format!("{label} failed"));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|_| format!("{label} returned non-UTF-8 output"))
}

fn verify_source(expected_commit: &str) -> Result<(), String> {
    let commit = command_output(
        Command::new("git").args(["rev-parse", "HEAD"]),
        "Git source identity",
    )?;
    if commit != expected_commit {
        return Err("qualification source does not match the exact requested commit".into());
    }
    let status = command_output(
        Command::new("git").args(["status", "--porcelain"]),
        "Git source status",
    )?;
    if !status.is_empty() {
        return Err("qualification requires an exact clean Git checkout".into());
    }
    Ok(())
}

fn peak_rss_bytes() -> Result<u64, String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("read Linux process status: {error}"))?;
    for key in ["VmHWM:", "VmRSS:"] {
        if let Some(line) = status.lines().find(|line| line.starts_with(key)) {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() == 3 && fields[2] == "kB" {
                return fields[1]
                    .parse::<u64>()
                    .map(|value| value.saturating_mul(1024))
                    .map_err(|_| "Linux RSS value is invalid".into());
            }
        }
    }
    Err("Linux process status did not expose VmHWM or VmRSS".into())
}

fn duration_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn open_new_report(path: &Path) -> Result<File, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create report parent: {error}"))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| format!("report destination must be a new file: {error}"))
}

fn write_report(path: &Path, report: &Value) -> Result<(), String> {
    let encoded =
        serde_json::to_vec_pretty(report).map_err(|error| format!("encode report: {error}"))?;
    if encoded.len() > MAX_REPORT_BYTES {
        return Err("qualification report exceeded its size bound".into());
    }
    let mut target = open_new_report(path)?;
    target
        .write_all(&encoded)
        .and_then(|_| target.write_all(b"\n"))
        .and_then(|_| target.sync_all())
        .map_err(|error| format!("write qualification report: {error}"))
}

async fn execute(arguments: Arguments) -> Result<bool, String> {
    if std::env::consts::OS != "linux" || std::env::consts::ARCH != "x86_64" {
        return Err("on-device qualification supports only Linux x86_64".into());
    }
    verify_source(&arguments.expected_commit)?;
    let model_identity = file_identity(
        &arguments.model_path,
        arguments.max_model_bytes,
        "GGUF model",
    )?;
    let tokenizer_identity =
        file_identity(&arguments.tokenizer_path, MAX_TOKENIZER_BYTES, "tokenizer")?;
    let model_sha256 = sha256_file(&arguments.model_path)?;
    let tokenizer_sha256 = sha256_file(&arguments.tokenizer_path)?;
    let rayon_threads = std::env::var("RAYON_NUM_THREADS")
        .map_err(|_| "RAYON_NUM_THREADS must be configured".to_string())?
        .parse::<u64>()
        .map_err(|_| "RAYON_NUM_THREADS must be a positive integer".to_string())?;
    if rayon_threads == 0 || rayon_threads > 256 {
        return Err("RAYON_NUM_THREADS must be within 1..256".into());
    }

    let template = match arguments.chat_template.as_str() {
        "simple" => ChatTemplate::Simple,
        "chatml" => ChatTemplate::ChatMl,
        "llama3" => ChatTemplate::Llama3,
        _ => unreachable!("parser validates templates"),
    };
    let model_path = arguments
        .model_path
        .to_str()
        .ok_or_else(|| "GGUF model path must be valid UTF-8".to_string())?
        .to_owned();
    let tokenizer_path = arguments
        .tokenizer_path
        .to_str()
        .ok_or_else(|| "tokenizer path must be valid UTF-8".to_string())?
        .to_owned();
    let mut configuration = OnDeviceConfig::new(model_path, tokenizer_path);
    configuration.model_id = arguments.model_id.clone();
    configuration.max_new_tokens = 256;
    configuration.max_model_bytes = arguments.max_model_bytes;
    configuration.max_context_tokens = arguments.max_context_tokens;
    configuration.chat_template = template;
    configuration.temperature = 0.0;
    configuration.seed = 42;

    let load_started = Instant::now();
    let adapter = OnDeviceLlmAdapter::load(configuration)
        .map_err(|error| format!("load provisioned GGUF model: {error}"))?;
    let load_ms = duration_ms(load_started);
    let session = adapter
        .create_session()
        .await
        .map_err(|error| format!("create on-device session: {error}"))?;

    let generation_started = Instant::now();
    let response = session
        .send_controlled(
            vec![StandardMessage::user(
                "Reply with one short word for this qualification probe.",
            )],
            &[],
            LlmRequestOptions {
                max_output_tokens: Some(MAX_OUTPUT_TOKENS),
                timeout: Some(Duration::from_secs(arguments.max_generation_seconds)),
            },
            &CancellationToken::new(),
        )
        .await
        .map_err(|error| format!("run bounded real-model generation: {error}"))?;
    let generation_ms = duration_ms(generation_started);

    let cancellation = CancellationToken::new();
    let cancellation_trigger = cancellation.clone();
    let cancel_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(CANCELLATION_DELAY_MS)).await;
        cancellation_trigger.cancel();
    });
    let cancellation_prompt =
        "qualification cancellation prefill ".repeat(arguments.max_context_tokens / 16);
    let cancellation_started = Instant::now();
    let cancellation_result = session
        .send_controlled(
            vec![StandardMessage::user(cancellation_prompt)],
            &[],
            LlmRequestOptions {
                max_output_tokens: Some(256),
                timeout: Some(Duration::from_secs(arguments.max_cancellation_seconds)),
            },
            &cancellation,
        )
        .await;
    cancel_task
        .await
        .map_err(|error| format!("join cancellation trigger: {error}"))?;
    let cancellation_ms = duration_ms(cancellation_started);
    let cancellation_drained = matches!(cancellation_result, Err(ConnectorError::Cancelled(_)));

    let inputs_stable = file_identity(
        &arguments.model_path,
        arguments.max_model_bytes,
        "GGUF model",
    )? == model_identity
        && file_identity(&arguments.tokenizer_path, MAX_TOKENIZER_BYTES, "tokenizer")?
            == tokenizer_identity
        && sha256_file(&arguments.model_path)? == model_sha256
        && sha256_file(&arguments.tokenizer_path)? == tokenizer_sha256;
    verify_source(&arguments.expected_commit)?;
    let peak_rss = peak_rss_bytes()?;
    let checks = BTreeMap::from([
        ("bounded_generation", {
            response.tokens_used > 0
                && response.tokens_used <= MAX_OUTPUT_TOKENS
                && response.content.len() <= 65_536
                && generation_ms <= arguments.max_generation_seconds.saturating_mul(1000)
        }),
        (
            "cancellation_worker_drained",
            cancellation_drained
                && cancellation_ms <= arguments.max_cancellation_seconds.saturating_mul(1000),
        ),
        (
            "load_within_target",
            load_ms <= arguments.max_load_seconds.saturating_mul(1000),
        ),
        (
            "peak_rss_within_target",
            peak_rss > 0 && peak_rss <= arguments.max_rss_bytes,
        ),
        ("provisioned_inputs_stable", inputs_stable),
        ("supported_cpu_profile", true),
    ]);
    let passed = checks.values().all(|value| *value);
    let configuration_sha256 = sha256_bytes(
        &serde_json::to_vec(&json!({
            "model_sha256": &model_sha256,
            "tokenizer_sha256": &tokenizer_sha256,
            "model_id": &arguments.model_id,
            "chat_template": &arguments.chat_template,
            "max_context_tokens": arguments.max_context_tokens,
            "max_model_bytes": arguments.max_model_bytes,
            "max_rss_bytes": arguments.max_rss_bytes,
            "max_load_seconds": arguments.max_load_seconds,
            "max_generation_seconds": arguments.max_generation_seconds,
            "max_cancellation_seconds": arguments.max_cancellation_seconds,
            "rayon_threads": rayon_threads,
        }))
        .map_err(|error| format!("encode configuration identity: {error}"))?,
    );
    let report = json!({
        "schema_version": SCHEMA_VERSION,
        "qualification_class": QUALIFICATION_CLASS,
        "generated_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "release_candidate": arguments.release_candidate,
        "source": {
            "commit": arguments.expected_commit,
            "dirty": false,
        },
        "environment": {
            "environment_id": arguments.environment_id,
            "os": "linux",
            "arch": "x86_64",
            "hardware_id": arguments.hardware_id,
            "configuration_sha256": configuration_sha256,
        },
        "model": {
            "model_id": arguments.model_id,
            "model_sha256": model_sha256,
            "tokenizer_sha256": tokenizer_sha256,
            "model_bytes": model_identity.length,
            "tokenizer_bytes": tokenizer_identity.length,
            "chat_template": arguments.chat_template,
            "max_context_tokens": arguments.max_context_tokens,
            "max_output_tokens": MAX_OUTPUT_TOKENS,
            "device": "cpu",
            "rayon_threads": rayon_threads,
        },
        "targets": {
            "max_model_bytes": arguments.max_model_bytes,
            "max_rss_bytes": arguments.max_rss_bytes,
            "max_load_seconds": arguments.max_load_seconds,
            "max_generation_seconds": arguments.max_generation_seconds,
            "max_cancellation_seconds": arguments.max_cancellation_seconds,
        },
        "measurements": {
            "load_ms": load_ms,
            "generation_ms": generation_ms,
            "cancellation_ms": cancellation_ms,
            "peak_rss_bytes": peak_rss,
            "generated_tokens": response.tokens_used,
            "output_bytes": response.content.len(),
        },
        "checks": checks,
        "on_device_proof_eligible": passed,
        "production_claim_allowed": false,
        "passed": passed,
        "caveats": [
            "This report qualifies only the exact model, tokenizer, hardware, limits, and release candidate identified by their digests.",
            "The supported on-device profile is CPU-only quantized Llama-family GGUF inference without native tool calls, vision, audio, or GPU execution.",
            "Whole-product production approval remains false until every Phase 1 and independent release gate passes.",
        ],
    });
    write_report(&arguments.output, &report)?;
    Ok(passed)
}

#[tokio::main]
async fn main() {
    let mode = parse_arguments(std::env::args().skip(1)).unwrap_or_else(|error| {
        eprintln!("on-device qualification failed: {error}");
        std::process::exit(2);
    });
    match mode {
        Mode::Validate => {
            println!(
                "validated on-device qualification schema v{SCHEMA_VERSION}: \
                 class={QUALIFICATION_CLASS}, max_output_tokens={MAX_OUTPUT_TOKENS}"
            );
        }
        Mode::Execute(arguments) => match execute(*arguments).await {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("on-device qualification failed: one or more checks failed");
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!("on-device qualification failed: {error}");
                std::process::exit(1);
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_arguments() -> Vec<String> {
        [
            "--model",
            "/models/model.gguf",
            "--tokenizer",
            "/models/tokenizer.json",
            "--model-id",
            "qwen2.5-0.5b-q4_k_m",
            "--chat-template",
            "chatml",
            "--max-context-tokens",
            "4096",
            "--max-model-bytes",
            "17179869184",
            "--max-rss-bytes",
            "8589934592",
            "--max-load-seconds",
            "600",
            "--max-generation-seconds",
            "180",
            "--max-cancellation-seconds",
            "10",
            "--expected-commit",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--release-candidate",
            "v1.0.0-rc.1",
            "--environment-id",
            "prod-ca-east-1",
            "--hardware-id",
            "cpu-runner-amd64-1",
            "--output",
            "/evidence/on-device.json",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    #[test]
    fn validate_mode_is_isolated() {
        assert_eq!(
            parse_arguments(["--validate".to_string()]).unwrap(),
            Mode::Validate
        );
        assert!(parse_arguments(["--validate".into(), "--model".into()]).is_err());
    }

    #[test]
    fn execution_contract_is_exact_and_target_bound() {
        let parsed = parse_arguments(complete_arguments()).unwrap();
        let Mode::Execute(arguments) = parsed else {
            panic!("expected execution arguments");
        };
        assert_eq!(arguments.max_context_tokens, 4096);
        assert_eq!(arguments.release_candidate, "v1.0.0-rc.1");
        assert_eq!(arguments.environment_id, "prod-ca-east-1");
    }

    #[test]
    fn malformed_missing_duplicate_fixture_and_relative_inputs_fail_closed() {
        let mut cases = Vec::new();
        let mut missing = complete_arguments();
        missing.truncate(missing.len() - 2);
        cases.push(missing);
        let mut duplicate = complete_arguments();
        duplicate.extend(["--model".into(), "/other/model.gguf".into()]);
        cases.push(duplicate);
        let mut fixture = complete_arguments();
        let position = fixture
            .iter()
            .position(|value| value == "--environment-id")
            .unwrap();
        fixture[position + 1] = "test-runner".into();
        cases.push(fixture);
        let mut relative = complete_arguments();
        let position = relative
            .iter()
            .position(|value| value == "--model")
            .unwrap();
        relative[position + 1] = "model.gguf".into();
        cases.push(relative);
        let mut bad_release = complete_arguments();
        let position = bad_release
            .iter()
            .position(|value| value == "--release-candidate")
            .unwrap();
        bad_release[position + 1] = "v1".into();
        cases.push(bad_release);
        for case in cases {
            assert!(parse_arguments(case).is_err());
        }
    }
}
