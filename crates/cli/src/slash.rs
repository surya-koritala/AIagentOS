//! Shared REPL and one-shot slash command dispatch. Success follows the
//! completed operation, including durable correction-file publication.

use kernel::learning::RuleStore;
use kernel::{AgentId, AgentKernelImpl};

pub const COMMANDS: &[&str] = &[
    "/quit", "/exit", "/id", "/history", "/usage", "/plan", "/learn", "/unlearn", "/help",
];
pub const HELP: &str = "Commands:\n  /quit, /exit  Exit\n  /id           Show conversation ID\n  /history      List local tenant conversations\n  /usage        Show recorded token usage and cost\n  /plan TASK    Generate steps; step execution is not wired\n  /learn        List this local operator's corrections\n  /learn T C    Persist correction (one-word trigger, remaining correction text)\n  /unlearn ID   Remove a persisted correction by UUID\n  /help         Show these commands";

#[derive(Debug, PartialEq, Eq)]
pub enum SlashOutcome {
    NotSlash,
    Quit,
    Output(String),
}

pub async fn handle_slash(
    input: &str,
    kernel: &AgentKernelImpl,
    agent: AgentId,
    conversation: &str,
    rules: &RuleStore,
) -> Result<SlashOutcome, String> {
    let input = input.trim();
    if !input.starts_with('/') {
        return Ok(SlashOutcome::NotSlash);
    }
    let (command, argument) = input
        .split_once(char::is_whitespace)
        .map_or((input, ""), |(command, argument)| {
            (command, argument.trim())
        });
    if input.len() > kernel::planning::MAX_PLAN_TASK_BYTES + 16 {
        return Err("slash command exceeds the input bound".into());
    }
    let output = match command {
        "/quit" | "/exit" => {
            require_no_argument(argument)?;
            return Ok(SlashOutcome::Quit);
        }
        "/help" => {
            require_no_argument(argument)?;
            HELP.to_string()
        }
        "/id" => {
            require_no_argument(argument)?;
            conversation.to_string()
        }
        "/history" => {
            require_no_argument(argument)?;
            let mut result = String::from("Local tenant conversations:\n");
            for (id, owner, updated) in kernel
                .context_manager
                .list_conversations()
                .into_iter()
                .filter(|(_, owner, _)| {
                    owner.parse::<AgentId>().ok().is_some_and(|owner| {
                        kernel
                            .context_manager
                            .agent_tenant(owner)
                            .ok()
                            .flatten()
                            .as_deref()
                            == Some(kernel::context::DEFAULT_TENANT)
                    })
                })
                .take(10)
            {
                result.push_str(&format!("  {id} (agent {owner}, {updated})\n"));
            }
            result
        }
        "/usage" => {
            require_no_argument(argument)?;
            let (tokens, cost) = kernel.context_manager.get_total_usage();
            let stats = kernel.rate_limiter.stats();
            format!(
                "Tokens: {tokens} | Cost: ${cost:.4} | RPM: {}/{}",
                stats.requests_this_minute, stats.rpm_limit
            )
        }
        "/learn" if argument.is_empty() => {
            rules.check_health().map_err(|error| error.to_string())?;
            let current = rules.get_rules(Some(rules.scope()));
            if current.is_empty() {
                "No correction rules for this local operator.".into()
            } else {
                let mut result = format!("Correction rules ({}):\n", current.len());
                for rule in current {
                    result.push_str(&format!(
                        "  {} when '{}' -> '{}' (added by {}, {})\n",
                        rule.id, rule.trigger, rule.correction, rule.added_by, rule.created_at
                    ));
                }
                result
            }
        }
        "/learn" => {
            if !rules.is_durable() {
                return Err("Rule was not added: durable storage is unavailable".into());
            }
            let (trigger, correction) = argument
                .split_once(char::is_whitespace)
                .ok_or_else(|| "Use: /learn <trigger> <correction>".to_string())?;
            let id = rules
                .add_rule(
                    trigger.to_string(),
                    correction.trim().to_string(),
                    rules.scope().clone(),
                )
                .map_err(|error| format!("Rule persistence could not be confirmed: {error}"))?;
            format!("Rule persisted: {id}")
        }
        "/unlearn" => {
            if !rules.is_durable() {
                return Err("Rule was not removed: durable storage is unavailable".into());
            }
            if argument.is_empty() || argument.contains(char::is_whitespace) {
                return Err("Use: /unlearn <rule UUID>".into());
            }
            if rules
                .remove_rule(argument)
                .map_err(|error| format!("Rule removal could not be confirmed: {error}"))?
            {
                format!("Rule removed: {argument}")
            } else {
                return Err(format!("Rule not found: {argument}"));
            }
        }
        "/plan" => {
            let plan = kernel
                .generate_plan(agent, argument)
                .await
                .map_err(|error| format!("Plan generation failed: {error}"))?;
            let mut result = String::from("Generated plan:\n");
            for step in plan.steps {
                result.push_str(&format!(
                    "  {}. {} [risk: {:?}]\n",
                    step.number, step.description, step.risk_level
                ));
            }
            result.push_str("Plan execution is not wired. No plan steps were executed.");
            result
        }
        _ => return Err(format!("Unknown command '{command}'. Type /help.")),
    };
    Ok(SlashOutcome::Output(output))
}

fn require_no_argument(argument: &str) -> Result<(), String> {
    if argument.is_empty() {
        Ok(())
    } else {
        Err("This command accepts no arguments.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn slash_help_and_error_paths_never_claim_success() {
        let kernel = AgentKernelImpl::new().unwrap();
        let path =
            std::env::temp_dir().join(format!("agentos-slash-{}", kernel::AgentId::new_v4()));
        std::fs::create_dir(&path).unwrap();
        let rules = RuleStore::from_file(
            &path.join("rules.json"),
            kernel::learning::RuleScope::local_cli(),
            "local-cli",
        )
        .unwrap();
        let agent = AgentId::new_v4();
        for command in COMMANDS {
            assert!(HELP.contains(command), "missing {command}");
        }
        assert_eq!(
            handle_slash("/help", &kernel, agent, "conversation", &rules)
                .await
                .unwrap(),
            SlashOutcome::Output(HELP.into())
        );
        for command in [
            "/learn only-trigger",
            "/learn a",
            "/unlearn",
            "/unlearn invalid",
            "/plan",
            "/unknown",
            "/id extra",
        ] {
            assert!(
                handle_slash(command, &kernel, agent, "conversation", &rules)
                    .await
                    .is_err(),
                "{command} falsely succeeded"
            );
        }
        assert_eq!(
            handle_slash("/quit", &kernel, agent, "conversation", &rules)
                .await
                .unwrap(),
            SlashOutcome::Quit
        );
        assert_eq!(
            handle_slash("hello", &kernel, agent, "conversation", &rules)
                .await
                .unwrap(),
            SlashOutcome::NotSlash
        );
        let added = handle_slash("/learn a b", &kernel, agent, "conversation", &rules)
            .await
            .unwrap();
        assert!(matches!(added, SlashOutcome::Output(text) if text.starts_with("Rule persisted:")));
        assert_eq!(rules.get_rules(None).len(), 1);
        let id = rules.get_rules(None)[0].id.clone();
        assert!(handle_slash(
            &format!("/unlearn {id}"),
            &kernel,
            agent,
            "conversation",
            &rules
        )
        .await
        .is_ok());
        assert!(handle_slash(
            &format!("/unlearn {id}"),
            &kernel,
            agent,
            "conversation",
            &rules
        )
        .await
        .is_err());
        drop(rules);
        std::fs::remove_dir_all(path).unwrap();
    }
}
