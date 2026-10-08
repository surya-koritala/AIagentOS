use coding_agent::provider::{ProposalProvider, ProviderAudit};
use kernel::config::TokenPricing;
use kernel::connector::{LlmProviderAdapter, LlmRequestOptions, StandardMessage};
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn budget(limit: f64) -> Arc<kernel::budget::BudgetEnforcer> {
    let budget = Arc::new(kernel::budget::BudgetEnforcer::with_pricing(
        0.001, limit, 0.0,
    ));
    budget
        .set_provider_token_pricing(
            "coding",
            TokenPricing {
                input_usd_per_1k_tokens: 0.001,
                cached_input_usd_per_1k_tokens: 0.001,
                output_usd_per_1k_tokens: 0.001,
            },
        )
        .unwrap();
    budget
}
async fn response(
    value: serde_json::Value,
    limit: f64,
) -> (
    Result<kernel::connector::LlmResponse, kernel::ConnectorError>,
    MockServer,
) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(value))
        .mount(&server)
        .await;
    let adapter = adapters::openai::OpenAiAdapter::new("fixture-key".into())
        .with_base_url(server.uri())
        .with_model("coding-contract-model".into());
    let audit = Arc::new(ProviderAudit::default());
    let provider =
        ProposalProvider::real(Arc::new(adapter), budget(limit)).with_audit(audit.clone());
    let session = provider.create_session().await.unwrap();
    let result = session
        .send_with_options(
            vec![StandardMessage::user("bounded task")],
            &[],
            LlmRequestOptions {
                max_output_tokens: Some(512),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(
        audit.api_calls(),
        server.received_requests().await.unwrap().len() as u64
    );
    (result, server)
}
fn reply(content: &str) -> serde_json::Value {
    serde_json::json!({"choices":[{"message":{"role":"assistant","content":content},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":10,"total_tokens":20}})
}

#[tokio::test]
async fn malformed_and_textual_tool_replies_fail_before_executor_effects() {
    for content in [
        "not JSON",
        "{\"tool\":\"write_file\",\"arguments\":{\"path\":\"outside\",\"content\":\"secret\"}}",
    ] {
        let (result, server) = response(reply(content), 1.0).await;
        assert!(result.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
#[tokio::test]
async fn native_tool_calls_are_rejected_even_when_content_is_a_valid_proposal() {
    let mut value = reply("{\"edits\":[]}");
    value["choices"][0]["message"]["tool_calls"] = serde_json::json!([{"id":"fixture-call","type":"function","function":{"name":"write_file","arguments":"{\"path\":\"outside\",\"content\":\"secret\"}"}}]);
    let (result, _) = response(value, 1.0).await;
    assert!(result.unwrap_err().to_string().contains("executable"));
}
#[tokio::test]
async fn configured_budget_denies_the_request_before_any_provider_io() {
    let (result, server) = response(reply("{\"edits\":[]}"), 0.000001).await;
    assert!(result.unwrap_err().to_string().contains("budget exhausted"));
    assert!(server.received_requests().await.unwrap().is_empty());
}
#[tokio::test]
async fn valid_proposals_preserve_reported_usage_and_receive_no_tool_declarations() {
    let (result, server) = response(reply("{\"edits\":[]}"), 1.0).await;
    let response = result.unwrap();
    assert_eq!(response.tokens_used, 20);
    assert!(response.tool_calls.is_empty());
    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert!(body.get("tools").is_none());
    assert_eq!(body["max_tokens"], 512);
}
