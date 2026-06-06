//! Property suite for the declarative policy authoring surface.
//!
//! The whole point of `kernel::policy::PolicyDocument` is that operators can
//! author, validate and *dry-run* a policy and trust that what `explain` tells
//! them matches what the live `MacEngine` will actually enforce. If those two
//! ever diverge the authoring tool is worse than useless — it is *misleading*.
//! So the load-bearing invariant proven here is:
//!
//!   For every document and every (subject, action, object) query,
//!   `document.explain(...)`.decision == an independently-built `MacEngine`
//!   loaded with the document's compiled rules, evaluated on the same inputs.
//!
//! The engine is the source of truth (it is what the syscall gate consults);
//! the document is an authoring layer that lowers to it. We generate random
//! documents (random subjects/actions/objects/decisions, random default and
//! enforcing flags) and random queries, then compare.
//!
//! Deterministic: proptest's seeded RNG, fresh engine per case, no clock.

use proptest::prelude::*;

use kernel::policy::{Decision, PolicyDocument, Rule};

// A small, fixed vocabulary keeps collisions (and therefore real rule matches)
// frequent, so the property exercises the matching path rather than almost
// always falling through to the default.
fn subjects() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_string()),
        Just("profile:read-only".to_string()),
        Just("profile:standard".to_string()),
        Just("profile:elevated".to_string()),
    ]
}

fn actions() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_string()),
        Just("read".to_string()),
        Just("write".to_string()),
        Just("execute".to_string()),
        Just("net".to_string()),
    ]
}

fn objects() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_string()),
        Just("/etc/**".to_string()),
        Just("/home/**".to_string()),
        Just("unconfined".to_string()),
        Just("filesystem".to_string()),
    ]
}

fn decisions() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        Just(Decision::Deny),
        Just(Decision::Audit),
    ]
}

prop_compose! {
    fn a_rule()(
        subject in subjects(),
        action in actions(),
        object in objects(),
        decision in decisions(),
        named in any::<bool>(),
    ) -> Rule {
        Rule {
            name: if named { Some(format!("r-{subject}-{action}")) } else { None },
            description: None,
            subject,
            action,
            object,
            decision,
        }
    }
}

prop_compose! {
    fn a_document()(
        rules in prop::collection::vec(a_rule(), 0..8),
        default in decisions(),
        enforcing in any::<bool>(),
    ) -> PolicyDocument {
        PolicyDocument {
            version: 1,
            description: None,
            enforcing,
            default,
            rules,
        }
    }
}

// Query objects include raw paths so the glob path is exercised, not just the
// label-equality path.
fn query_objects() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_string()),
        Just("filesystem".to_string()),
        Just("unconfined".to_string()),
        Just("/etc/ssl/key".to_string()),
        Just("/home/u/notes".to_string()),
        Just("/var/log/x".to_string()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// The authoring tool's `explain` must agree with the engine the document
    /// compiles to — for every document and every query.
    #[test]
    fn explain_agrees_with_compiled_engine(
        doc in a_document(),
        subject in subjects(),
        action in actions(),
        object in query_objects(),
    ) {
        let engine = doc.to_engine();
        // The engine's object semantics match on the label OR the raw resource;
        // `explain` passes the query object as both, so we do the same here.
        let (engine_decision, _matched) = engine.evaluate(&subject, &action, &object, &object);
        let explanation = doc.explain(&subject, &action, &object);
        prop_assert_eq!(
            explanation.decision,
            engine_decision,
            "explain disagreed with engine for subject={} action={} object={}",
            subject, action, object
        );
    }

    /// `compile` is faithful: a document with `default = deny` adds no synthetic
    /// rule (the engine is default-deny), while `allow`/`audit` add exactly one
    /// trailing catch-all. So the compiled length is rules + {0 or 1}.
    #[test]
    fn compile_length_tracks_default(doc in a_document()) {
        let extra = if doc.default == Decision::Deny { 0 } else { 1 };
        prop_assert_eq!(doc.compile().len(), doc.rules.len() + extra);
    }

    /// `explain` reports `used_default` iff no authored/synthetic rule matched,
    /// and a reported matched index is always in range.
    #[test]
    fn explain_matched_index_is_consistent(
        doc in a_document(),
        subject in subjects(),
        action in actions(),
        object in query_objects(),
    ) {
        let e = doc.explain(&subject, &action, &object);
        prop_assert_eq!(e.used_default, e.matched_rule.is_none());
        if let Some(i) = e.matched_rule {
            prop_assert!(i < doc.compile().len());
        }
    }
}
