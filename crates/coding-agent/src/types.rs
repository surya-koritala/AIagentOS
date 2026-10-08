use crate::{hash, Error};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const MAX_PROJECT_BYTES: usize = 128 * 1024;
pub const MAX_FILE_BYTES: usize = 32 * 1024;
pub const MAX_PROPOSAL_BYTES: usize = 128 * 1024;
pub const MAX_JOURNAL_BYTES: usize = 900 * 1024;
pub const MAX_LOG_BYTES: usize = 8192;
pub const JOURNAL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpec {
    pub instruction: String,
    pub files: Vec<String>,
    pub editable: Vec<String>,
    pub test_target: String,
    pub max_branches: u32,
    pub max_steps: u32,
    pub deadline_seconds: u64,
    pub max_usd: f64,
    pub max_output_tokens: u32,
}

pub fn safe_path(path: &str) -> Result<(), Error> {
    if path.is_empty() || path.len() > 512 || path.contains(['\\', ':', '\0']) {
        return Err(Error::Contract("invalid repository-relative path".into()));
    }
    for part in path.split('/') {
        let lower = part.to_ascii_lowercase();
        if part.is_empty()
            || matches!(part, "." | "..")
            || lower.starts_with('.')
            || matches!(
                lower.as_str(),
                "id_rsa" | "id_ed25519" | "credentials" | "credentials.json"
            )
            || lower.ends_with(".pem")
            || lower.ends_with(".key")
            || lower.ends_with(".p12")
        {
            return Err(Error::Contract(
                "undeclared filesystem or credential authority".into(),
            ));
        }
    }
    Ok(())
}

impl TaskSpec {
    pub fn validate(&self) -> Result<(), Error> {
        if self.instruction.is_empty()
            || self.instruction.len() > 4096
            || !(1..=32).contains(&self.files.len())
            || self.editable.is_empty()
            || !(1..=4).contains(&self.max_branches)
            || !(32..=4096).contains(&self.max_steps)
            || !(30..=1800).contains(&self.deadline_seconds)
            || !self.max_usd.is_finite()
            || self.max_usd <= 0.0
            || self.max_usd > 100.0
            || !(64..=8192).contains(&self.max_output_tokens)
            || self.test_target.is_empty()
            || self.test_target.len() > 128
            || !self
                .test_target
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(Error::Contract("invalid explicit task bounds".into()));
        }
        let files = self.files.iter().collect::<BTreeSet<_>>();
        let editable = self.editable.iter().collect::<BTreeSet<_>>();
        if files.len() != self.files.len()
            || editable.len() != self.editable.len()
            || !editable.is_subset(&files)
        {
            return Err(Error::Contract(
                "duplicate or undeclared editable file".into(),
            ));
        }
        for path in &self.files {
            safe_path(path)?;
        }
        if self.editable.iter().any(|path| {
            path.starts_with("tests/")
                || path.ends_with("Cargo.toml")
                || path.ends_with("Cargo.lock")
        }) {
            return Err(Error::Contract(
                "tests and dependency manifests are immutable".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEdit {
    pub path: String,
    pub expected_sha256: String,
    pub replacement: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub edits: Vec<FileEdit>,
}
impl Proposal {
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_PROPOSAL_BYTES {
            return Err(Error::Contract("proposal exceeds byte bound".into()));
        }
        Ok(serde_json::from_str(text)?)
    }
    pub fn validate(&self, spec: &TaskSpec, files: &BTreeMap<String, String>) -> Result<(), Error> {
        if self.edits.is_empty() || self.edits.len() > spec.editable.len() {
            return Err(Error::Contract(
                "candidate must edit a declared source file".into(),
            ));
        }
        let mut paths = BTreeSet::new();
        let mut bytes = 0;
        for edit in &self.edits {
            safe_path(&edit.path)?;
            let original = files
                .get(&edit.path)
                .ok_or_else(|| Error::Contract("edit target is absent".into()))?;
            if !spec.editable.contains(&edit.path)
                || !paths.insert(&edit.path)
                || edit.expected_sha256 != hash(original.as_bytes())
                || edit.replacement.len() > MAX_FILE_BYTES
                || edit.replacement == *original
            {
                return Err(Error::Contract(
                    "edit violates source scope or preimage".into(),
                ));
            }
            bytes += edit.replacement.len();
        }
        if bytes > MAX_PROJECT_BYTES {
            return Err(Error::Contract("candidate exceeds project bound".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Captured,
    Preparing,
    Proposing,
    Proposed,
    Applying,
    Testing,
    Tested,
    Discarding,
    Discarded,
    Selected,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestEvidence {
    pub operation_id: Uuid,
    pub kind: String,
    pub tool: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stdout: String,
    pub stderr: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    pub id: Uuid,
    pub owned: bool,
    pub index: u32,
    pub phase: Phase,
    pub seeded: BTreeSet<String>,
    pub proposal: Option<Proposal>,
    pub applied: BTreeSet<String>,
    pub test: Option<TestEvidence>,
    pub request_id: String,
    pub test_operation: Uuid,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub at: DateTime<Utc>,
    pub agent: Uuid,
    pub action: String,
    pub detail: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Journal {
    pub version: u32,
    pub id: Uuid,
    pub parent: Uuid,
    pub spec: TaskSpec,
    pub image: String,
    pub mode: String,
    pub model: Option<String>,
    pub created: DateTime<Utc>,
    pub files: BTreeMap<String, String>,
    pub branches: Vec<Branch>,
    pub events: Vec<Event>,
    pub steps: u32,
    pub provider_tokens: u64,
    pub selected: Option<Uuid>,
    pub status: String,
}
impl Journal {
    pub fn validate(&self) -> Result<(), Error> {
        self.spec.validate()?;
        if self.version != JOURNAL_VERSION
            || self.id.is_nil()
            || self.parent.is_nil()
            || self.branches.len() > self.spec.max_branches as usize
            || self.files.len() != self.spec.files.len()
            || self.files.iter().any(|(path, content)| {
                !self.spec.files.contains(path) || content.len() > MAX_FILE_BYTES
            })
            || self.files.values().map(String::len).sum::<usize>() > MAX_PROJECT_BYTES
        {
            return Err(Error::Contract(
                "invalid durable task identity or corpus".into(),
            ));
        }
        let mut ids = BTreeSet::new();
        for (index, branch) in self.branches.iter().enumerate() {
            if branch.id.is_nil()
                || branch.id == self.parent
                || !ids.insert(branch.id)
                || branch.index != index as u32
            {
                return Err(Error::Contract("invalid owned branch identity".into()));
            }
            if branch
                .seeded
                .iter()
                .any(|path| !self.spec.files.contains(path))
                || branch
                    .applied
                    .iter()
                    .any(|path| !self.spec.editable.contains(path))
                || (branch.phase != Phase::Preparing && !branch.owned)
                || branch.test.as_ref().is_some_and(|test| {
                    test.stdout.len() > MAX_LOG_BYTES
                        || test.stderr.len() > MAX_LOG_BYTES
                        || test.operation_id != branch.test_operation
                })
                || (matches!(branch.phase, Phase::Tested | Phase::Selected)
                    && branch.test.is_none())
            {
                return Err(Error::Contract(
                    "invalid branch receipts or declared effect scope".into(),
                ));
            }
            if let Some(proposal) = &branch.proposal {
                proposal.validate(&self.spec, &self.files)?;
            }
        }
        if self.selected.is_some_and(|selected| {
            !self.branches.iter().any(|branch| {
                branch.id == selected
                    && branch.phase == Phase::Selected
                    && branch.owned
                    && branch.test.as_ref().is_some_and(|test| test.exit_code == 0)
            })
        }) {
            return Err(Error::Contract(
                "selected branch lacks passing evidence".into(),
            ));
        }
        Ok(())
    }
    pub fn event(&mut self, agent: Uuid, action: &str, detail: &str) {
        if self.events.len() == 128 {
            self.events.remove(0);
        }
        self.events.push(Event {
            at: Utc::now(),
            agent,
            action: action.into(),
            detail: detail.chars().take(512).collect(),
        });
    }
}
