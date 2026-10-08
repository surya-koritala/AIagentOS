//! Public evidence declarations are checked against the existing registry.

use super::{load_registry, read_workspace_file, workspace_root, Registry, MATURITY_MODEL};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const TABLE_START: &str = "<!-- capability-status:start -->";
const TABLE_END: &str = "<!-- capability-status:end -->";
const CLAIM_START: &str = "<!-- capability-claim:";

fn label(tier: &str) -> &str {
    match tier {
        "scaffolded" => "Scaffolded",
        "unit-tested" => "Unit-tested",
        "integrated" => "Integrated",
        "public-api-e2e" => "Public-API E2E",
        "production-qualified" => "Production-qualified",
        _ => panic!("unknown evidence tier {tier}"),
    }
}

fn readme_table(registry: &Registry) -> String {
    let mut result = String::from(
        "| Capability | Recorded evidence tier | Qualification owner |\n|---|---|---|\n",
    );
    for capability in &registry.capability {
        let qualification = capability
            .qualification_issue
            .unwrap_or(capability.tracking_issue);
        result.push_str(&format!(
            "| <!-- capability-claim: {}={} -->[{}](https://github.com/surya-koritala/AIagentOS/issues/{}) | {} | [#{}](https://github.com/surya-koritala/AIagentOS/issues/{}) |\n",
            capability.id, capability.maturity, capability.title, capability.tracking_issue,
            label(&capability.maturity), qualification, qualification,
        ));
    }
    result
}

fn readme_errors(registry: &Registry, readme: &str) -> Vec<String> {
    let Some((_, body)) = readme.split_once(TABLE_START) else {
        return vec!["README.md: missing registry-derived capability status block".into()];
    };
    let Some((actual, _)) = body.split_once(TABLE_END) else {
        return vec!["README.md: missing capability status end marker".into()];
    };
    if actual.trim() == readme_table(registry).trim() {
        Vec::new()
    } else {
        vec!["README.md: capability status rows disagree with docs/capabilities.toml".into()]
    }
}

fn claim_errors(registry: &Registry, path: &str, text: &str) -> Vec<String> {
    let ceilings = registry
        .capability
        .iter()
        .map(|entry| (entry.id.as_str(), entry.maturity.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut errors = Vec::new();
    let mut fenced = false;
    let mut status_columns = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let mut remainder = line;
        let mut declared = false;
        while let Some((_, after)) = remainder.split_once(CLAIM_START) {
            declared = true;
            let Some((claim, tail)) = after.split_once("-->") else {
                errors.push(format!(
                    "{path}:{}: unterminated capability claim",
                    index + 1
                ));
                break;
            };
            remainder = tail;
            let Some((id, tier)) = claim.trim().split_once('=') else {
                errors.push(format!(
                    "{path}:{}: capability claim requires id=tier",
                    index + 1
                ));
                continue;
            };
            let (id, tier) = (id.trim(), tier.trim());
            let Some(ceiling) = ceilings.get(id) else {
                errors.push(format!("{path}:{}: unknown capability {id}", index + 1));
                continue;
            };
            let Some(level) = MATURITY_MODEL
                .iter()
                .position(|candidate| *candidate == tier)
            else {
                errors.push(format!("{path}:{}: unknown claim tier {tier}", index + 1));
                continue;
            };
            let maximum = MATURITY_MODEL
                .iter()
                .position(|candidate| candidate == ceiling)
                .unwrap();
            if level > maximum {
                errors.push(format!(
                    "{path}:{}: {id} claims {tier} above recorded {ceiling}",
                    index + 1
                ));
            }
            if !line.contains(label(tier)) {
                errors.push(format!(
                    "{path}:{}: {id} must show its declared {} tier visibly",
                    index + 1,
                    label(tier)
                ));
            }
            let visible = line.split("-->").last().unwrap_or(line);
            for (visible_level, candidate) in MATURITY_MODEL.iter().enumerate() {
                if visible.contains(label(candidate)) && visible_level > level {
                    errors.push(format!(
                        "{path}:{}: visible {} exceeds declared {tier}",
                        index + 1,
                        label(candidate)
                    ));
                }
            }
        }
        // Bare current-status cells must be bound to an explicit capability.
        // Host requirements, ordinary runtime verbs, and conditional contracts
        // are not maturity declarations.
        if line.trim_start().starts_with('|') {
            let cells = line
                .split('|')
                .skip(1)
                .map(|cell| cell.trim().replace("**", "").trim_matches('`').to_string())
                .collect::<Vec<_>>();
            let headers = cells
                .iter()
                .enumerate()
                .filter_map(|(column, cell)| {
                    matches!(
                        cell.to_ascii_lowercase().as_str(),
                        "status"
                            | "maturity"
                            | "recorded evidence tier"
                            | "v1 disposition / limitation"
                    )
                    .then_some(column)
                })
                .collect::<Vec<_>>();
            if !headers.is_empty() {
                status_columns = headers;
            }
            if declared {
                continue;
            }
            for column in &status_columns {
                let Some(cell) = cells.get(*column) else {
                    continue;
                };
                let lower = cell.to_ascii_lowercase();
                if [
                    "scaffolded",
                    "unit-tested",
                    "integrated",
                    "public-api e2e",
                    "production-qualified",
                    "e2e verified",
                    "e2e-qualified",
                    "done",
                    "live",
                ]
                .iter()
                .any(|word| {
                    lower.strip_prefix(word).is_some_and(|tail| {
                        tail.is_empty()
                            || tail.chars().next().is_some_and(|character| {
                                matches!(character, ' ' | '.' | ';' | ':' | '(' | '—')
                            })
                    })
                }) && ![
                        "not ",
                        "pending",
                        "requires",
                        "until",
                        "remain",
                        "future",
                        "conditional",
                    ]
                    .iter()
                    .any(|condition| lower.contains(condition))
                {
                        errors.push(format!(
                            "{path}:{}: unbound current evidence status {cell:?}",
                            index + 1
                        ));
                }
            }
        } else {
            status_columns.clear();
        }
    }
    errors
}

#[derive(Deserialize)]
struct Inventory {
    schema_version: u32,
    surface: Vec<Surface>,
}
#[derive(Deserialize)]
struct Surface {
    path: String,
    kind: String,
}

fn markdown_files(directory: &Path, root: &Path, found: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        assert!(
            !kind.is_symlink(),
            "public documentation must have an explicit regular-file inventory"
        );
        if kind.is_dir() {
            markdown_files(&entry.path(), root, found);
        } else if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "md")
        {
            found.insert(
                entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

#[test]
fn public_surfaces_and_declared_tiers_are_complete_and_honest() {
    let root = workspace_root();
    let registry = load_registry();
    let inventory: Inventory =
        toml::from_str(&read_workspace_file("docs/public-claims.toml")).unwrap();
    assert_eq!(inventory.schema_version, 1);
    let mut expected = BTreeSet::from(["README.md".to_string()]);
    markdown_files(&root.join("docs"), &root, &mut expected);
    let declared = inventory
        .surface
        .iter()
        .map(|surface| surface.path.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        inventory.surface.len(),
        declared.len(),
        "duplicate public surface inventory"
    );
    assert_eq!(
        declared, expected,
        "public Markdown addition/removal requires an explicit evidence audit"
    );
    let mut errors = readme_errors(&registry, &read_workspace_file("README.md"));
    for surface in inventory.surface {
        let text = read_workspace_file(&surface.path);
        match surface.kind.as_str() {
            "current" => errors.extend(claim_errors(&registry, &surface.path, &text)),
            "historical" => {
                let heading = text.lines().take(14).collect::<Vec<_>>().join("\n");
                assert!(
                    heading.contains("Historical")
                        && heading.contains("issues/105")
                        && heading.contains("capabilities.toml"),
                    "{} must mark historical plans and point to current evidence",
                    surface.path
                );
            }
            other => panic!("unknown public surface kind {other}"),
        }
    }
    assert!(
        errors.is_empty(),
        "unsupported public capability claims: {errors:#?}"
    );
}

#[test]
fn a_real_registry_downgrade_names_affected_public_paths() {
    let mut registry = load_registry();
    registry
        .capability
        .iter_mut()
        .find(|entry| entry.id == "tool-vfs")
        .unwrap()
        .maturity = "unit-tested".into();
    let mut errors = readme_errors(&registry, &read_workspace_file("README.md"));
    errors.extend(claim_errors(
        &registry,
        "docs/VFS.md",
        &read_workspace_file("docs/VFS.md"),
    ));
    assert!(errors.iter().any(|error| error.contains("README.md")));
    assert!(
        errors
            .iter()
            .any(|error| error.contains("docs/VFS.md")
                && error.contains("above recorded unit-tested"))
    );
}

#[test]
fn malformed_unknown_unbound_and_overstated_claims_fail_closed() {
    let registry = load_registry();
    for text in [
        "<!-- capability-claim: absent=integrated --> Integrated",
        "<!-- capability-claim: tool-vfs=production-qualified --> Production-qualified",
        "<!-- capability-claim: tool-vfs=unknown --> unknown",
        "<!-- capability-claim: tool-vfs integrated --> Integrated",
        "<!-- capability-claim: tool-vfs=integrated --> Production-qualified",
        "<!-- capability-claim: tool-vfs=integrated --> Integrated and Production-qualified",
        "| Feature | Status |\n| Feature | Done |",
    ] {
        assert!(
            !claim_errors(&registry, "docs/fake.md", text).is_empty(),
            "{text}"
        );
    }
    assert!(claim_errors(&registry, "docs/host.md", "Linux kernel requirements; supported host OS; live operator updates\n```sh\nwhile true; do echo ok; done\n```").is_empty());
}

#[test]
fn every_product_crate_has_an_accurate_runtime_description() {
    let root = workspace_root();
    for entry in std::fs::read_dir(root.join("crates")).unwrap() {
        let path = entry.unwrap().path().join("Cargo.toml");
        if !path.is_file() {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap();
        let manifest: toml::Value = toml::from_str(&source).unwrap();
        let description = manifest["package"]
            .get("description")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("{} lacks a public product description", path.display()));
        assert!(!description.trim().is_empty());
        let lower = description.to_ascii_lowercase();
        assert!(
            !lower.contains("operating system kernel")
                && !lower.contains("kernel-mode")
                && !lower.contains("production-qualified"),
            "{} overstates runtime/qualification framing",
            path.display()
        );
    }
}
