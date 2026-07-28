//! `agent policy …` — the operator-facing policy authoring surface.
//!
//! These subcommands let an operator validate and dry-run a declarative policy
//! document (see `docs/POLICY.md`) *without* booting a kernel or touching the
//! database — the SELinux `checkpolicy` / `sesearch` analogue:
//!
//! ```text
//! agent policy validate <file>
//! agent policy explain  <file> --subject <S> --action <A> --object <O>
//! ```
//!
//! Returns the process exit code (0 = success, 2 = usage error, 1 = failure).

use agent_cli::policy;
use kernel::policy::PolicyDocument;

/// Dispatch a `policy` subcommand. `args` is the full process argv; this is
/// only called when `args[1] == "policy"`. Returns the exit code to use.
pub fn run(args: &[String]) -> i32 {
    match args.get(2).map(String::as_str) {
        Some("validate") => validate(args.get(3)),
        Some("explain") | Some("check") => explain(args),
        Some("help") | None => {
            usage();
            0
        }
        Some(other) => {
            eprintln!("agent policy: unknown subcommand '{other}'\n");
            usage();
            2
        }
    }
}

fn usage() {
    eprintln!(
        "Usage:\n  \
         agent policy validate <file>\n  \
         agent policy explain  <file> --subject <S> --action <A> --object <O>\n\n\
         Validate or dry-run a declarative policy document (see docs/POLICY.md)."
    );
}

fn load(path: Option<&String>) -> Result<PolicyDocument, i32> {
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("agent policy: missing <file> argument\n");
            usage();
            return Err(2);
        }
    };
    policy::load_policy(path).map_err(|e| {
        eprintln!("\x1b[31m[x] {e}\x1b[0m");
        1
    })
}

fn validate(path: Option<&String>) -> i32 {
    let doc = match load(path) {
        Ok(d) => d,
        Err(code) => return code,
    };
    let report = policy::validate_document(&doc);
    let mode = if doc.enforcing {
        "enforcing"
    } else {
        "permissive"
    };
    println!(
        "\x1b[32m[OK] policy is valid\x1b[0m - version {}, {mode}, default = {:?}, {} rule(s)",
        doc.version,
        doc.default,
        doc.rules.len()
    );
    if report.warnings.is_empty() {
        0
    } else {
        println!(
            "\n\x1b[33m{} lint warning(s):\x1b[0m",
            report.warnings.len()
        );
        for l in &report.warnings {
            match l.rule_index {
                Some(i) => println!("  \x1b[33m![rule #{i}]\x1b[0m {}", l.message),
                None => println!("  \x1b[33m!\x1b[0m {}", l.message),
            }
        }
        // Lints are warnings, not failures - a linted policy still loads.
        0
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn explain(args: &[String]) -> i32 {
    let doc = match load(args.get(3)) {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (subject, action, object) = match (
        flag(args, "--subject"),
        flag(args, "--action"),
        flag(args, "--object"),
    ) {
        (Some(s), Some(a), Some(o)) => (s, a, o),
        _ => {
            eprintln!("agent policy explain: requires --subject, --action and --object\n");
            usage();
            return 2;
        }
    };
    let e = policy::explain_document(&doc, subject, action, object);
    let (color, verdict) = match e.decision.as_str() {
        "allow" => ("\x1b[32m", "ALLOW"),
        "deny" => ("\x1b[31m", "DENY"),
        "audit" => ("\x1b[33m", "AUDIT"),
        _ => unreachable!("shared policy reports return a canonical decision"),
    };
    println!("query: subject={subject} action={action} object={object}");
    println!("{color}=> {verdict}\x1b[0m");
    match (e.matched_rule, e.matched_name) {
        (Some(i), Some(name)) => println!("  decided by rule #{i} ({name})"),
        (Some(i), None) => println!("  decided by rule #{i}"),
        (None, _) => println!(
            "  decided by default (no rule matched) - default = {:?}",
            doc.default
        ),
    }
    0
}
