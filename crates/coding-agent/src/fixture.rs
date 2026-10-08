//! Public, dependency-free task corpus for reproducible application checks.

use crate::TaskSpec;
use std::collections::BTreeMap;

pub fn spec() -> TaskSpec {
    TaskSpec {
        instruction: "Fix bounded_prefix to return the maximal borrowed UTF-8 prefix within a byte budget, preserving its signature and all integration tests.".into(),
        files: vec!["Cargo.toml".into(), "Cargo.lock".into(), "src/lib.rs".into(), "tests/utf8_budget.rs".into()],
        editable: vec!["src/lib.rs".into()], test_target: "utf8_budget".into(), max_branches: 2,
        max_steps: 1024, deadline_seconds: 600, max_usd: 0.01, max_output_tokens: 2048,
    }
}
pub fn files() -> BTreeMap<String, String> {
    [
        (
            "Cargo.toml",
            include_str!("../../../fixtures/coding-agent/utf8-budget/Cargo.toml"),
        ),
        (
            "Cargo.lock",
            include_str!("../../../fixtures/coding-agent/utf8-budget/Cargo.lock"),
        ),
        (
            "src/lib.rs",
            include_str!("../../../fixtures/coding-agent/utf8-budget/src/lib.rs"),
        ),
        (
            "tests/utf8_budget.rs",
            include_str!("../../../fixtures/coding-agent/utf8-budget/tests/utf8_budget.rs"),
        ),
    ]
    .into_iter()
    .map(|(path, text)| (path.into(), text.into()))
    .collect()
}
