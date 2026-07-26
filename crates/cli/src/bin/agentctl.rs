//! Small operator CLI for the public agent lifecycle API.

use std::time::Duration;

use agent_cli::OperatorClient;

fn usage() -> ! {
    eprintln!(
        "usage: agentctl [--addr HOST:PORT] [--token TOKEN] \
         <list|inspect|pressure|tunables|tunable-set|tunable-rollback|tunable-history|status|pause|resume|stop|kill|wait|services|service-start|service-stop|service-restart|service-reload|service-history> [ARGS...]"
    );
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1).peekable();
    let mut addr = std::env::var("AGENTOS_ADDR").unwrap_or_else(|_| "127.0.0.1:7777".into());
    let mut token = std::env::var("AGENT_SERVER_TOKEN").ok();

    while matches!(args.peek().map(String::as_str), Some("--addr" | "--token")) {
        match args.next().as_deref() {
            Some("--addr") => addr = args.next().unwrap_or_else(|| usage()),
            Some("--token") => token = Some(args.next().unwrap_or_else(|| usage())),
            _ => unreachable!(),
        }
    }

    let command = args.next().unwrap_or_else(|| usage());
    let mut client = OperatorClient::connect(&addr, token.as_deref())
        .await
        .unwrap_or_else(|error| {
            eprintln!("agentctl: could not connect to {addr}: {error}");
            std::process::exit(1);
        });

    let result = match command.as_str() {
        "list" => {
            let agents = client
                .list_agents()
                .await
                .unwrap_or_else(|error| fail(error));
            for agent in agents {
                println!("{}\t{}\t{}", agent.id, agent.state, agent.name);
            }
            return;
        }
        "inspect" => {
            let snapshot = client
                .operator_snapshot()
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&snapshot).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "snapshot encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "pressure" => {
            let stats = client
                .context_pressure(args.next().unwrap_or_else(|| usage()))
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&stats).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "pressure encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "tunables" => {
            let tunables = client
                .list_operator_tunables()
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&tunables).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "tunable encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "tunable-set" => {
            let name = args.next().unwrap_or_else(|| usage());
            let value = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            let expected_revision = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            let tunable = client
                .set_operator_tunable(name, value, expected_revision)
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&tunable).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "tunable encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "tunable-rollback" => {
            let name = args.next().unwrap_or_else(|| usage());
            let target_revision = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            let expected_revision = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            let tunable = client
                .rollback_operator_tunable(name, target_revision, expected_revision)
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&tunable).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "tunable encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "tunable-history" => {
            let name = args.next();
            let limit = args
                .next()
                .as_deref()
                .unwrap_or("100")
                .parse::<usize>()
                .unwrap_or_else(|_| usage());
            let entries = client
                .operator_tunable_audit(name, limit)
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&entries).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "tunable audit encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "services" => {
            for service in client
                .list_services()
                .await
                .unwrap_or_else(|error| fail(error))
            {
                println!(
                    "{}\t{:?}\t{}\tready={}\thealthy={}\trestarts={}\tdesired={}",
                    service.name,
                    service.status,
                    service
                        .agent_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "-".into()),
                    service.ready,
                    service.healthy,
                    service.restart_count,
                    service.desired_running,
                );
            }
            return;
        }
        "service-start" => {
            let service = client
                .start_service(args.next().unwrap_or_else(|| usage()))
                .await
                .unwrap_or_else(|error| fail(error));
            println!("{}\t{:?}", service.name, service.status);
            return;
        }
        "service-stop" => {
            let service = client
                .stop_service(args.next().unwrap_or_else(|| usage()))
                .await
                .unwrap_or_else(|error| fail(error));
            println!("{}\t{:?}", service.name, service.status);
            return;
        }
        "service-restart" => {
            let service = client
                .restart_service(args.next().unwrap_or_else(|| usage()))
                .await
                .unwrap_or_else(|error| fail(error));
            println!("{}\t{:?}", service.name, service.status);
            return;
        }
        "service-reload" => {
            let order = client
                .reload_services()
                .await
                .unwrap_or_else(|error| fail(error));
            println!("{}", order.join("\n"));
            return;
        }
        "service-history" => {
            let name = args.next();
            let limit = args
                .next()
                .as_deref()
                .unwrap_or("100")
                .parse::<usize>()
                .unwrap_or_else(|_| usage());
            let history = client
                .service_history(name, limit)
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&history).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "service history encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "status" => {
            client
                .agent_status(args.next().unwrap_or_else(|| usage()))
                .await
        }
        "pause" => {
            client
                .pause_agent(args.next().unwrap_or_else(|| usage()))
                .await
        }
        "resume" => {
            client
                .resume_agent(args.next().unwrap_or_else(|| usage()))
                .await
        }
        "stop" => {
            client
                .stop_agent(args.next().unwrap_or_else(|| usage()))
                .await
        }
        "kill" => {
            client
                .kill_agent(args.next().unwrap_or_else(|| usage()))
                .await
        }
        "wait" => {
            let id = args.next().unwrap_or_else(|| usage());
            let timeout_ms = args
                .next()
                .as_deref()
                .unwrap_or("30000")
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            client
                .wait_agent(id, Duration::from_millis(timeout_ms))
                .await
        }
        _ => usage(),
    };

    println!("{}", result.unwrap_or_else(|error| fail(error)));
}

fn fail(error: agent_sdk::SdkError) -> ! {
    eprintln!("agentctl: {error}");
    std::process::exit(1);
}
