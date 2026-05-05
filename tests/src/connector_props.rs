//! Property-based tests for Connector (Properties 13, 14).
//!
//! Property 13: Provider protocol validation — compile-time via Rust traits.
//! Property 14: Protocol message translation round-trip — for any StandardMessage,
//! translate to provider format and back SHALL produce semantically equivalent message.

use proptest::prelude::*;

use kernel::connector::*;
use adapters::openai::OpenAiAdapter;
use adapters::anthropic::AnthropicAdapter;
use adapters::local::LocalLlmAdapter;

fn arb_standard_message() -> impl Strategy<Value = StandardMessage> {
    (
        prop_oneof![Just("user"), Just("assistant"), Just("system")],
        "[a-zA-Z0-9 .,!?]{5,100}",
    ).prop_map(|(role, content)| StandardMessage {
        role: role.to_string(),
        content,
        tool_call_id: None,
        tool_calls: None,
    })
}

proptest! {
    /// Property 13: Provider protocol validation is enforced at compile time
    /// by Rust's trait system. If a type implements LlmProviderAdapter, it has
    /// all required methods. This test verifies the adapters compile and implement
    /// the trait correctly.
    #[test]
    fn prop13_provider_protocol_validation(msg in arb_standard_message()) {
        // The fact that these compile proves Property 13
        let openai = OpenAiAdapter::new("test-key".to_string());
        let anthropic = AnthropicAdapter::new("test-key".to_string());
        let local = LocalLlmAdapter::new("http://localhost:11434".to_string(), "llama3".to_string());

        // All implement LlmProviderAdapter (compile-time check)
        let _: &dyn LlmProviderAdapter = &openai;
        let _: &dyn LlmProviderAdapter = &anthropic;
        let _: &dyn LlmProviderAdapter = &local;

        // Verify they have valid IDs
        prop_assert!(!openai.id().is_empty());
        prop_assert!(!anthropic.id().is_empty());
        prop_assert!(!local.id().is_empty());
    }

    /// Property 14: For any StandardMessage, translate to provider format and back
    /// SHALL produce semantically equivalent message.
    #[test]
    fn prop14_message_translation_round_trip(msg in arb_standard_message()) {
        // Test OpenAI adapter round-trip
        let openai = OpenAiAdapter::new("test-key".to_string());
        let provider_format = openai.translate_to_provider(&msg);
        let restored = openai.translate_from_provider(&provider_format);
        prop_assert!(restored.is_some(), "OpenAI: translation back should succeed");
        let restored = restored.unwrap();
        prop_assert_eq!(&restored.role, &msg.role, "OpenAI: role should match");
        prop_assert_eq!(&restored.content, &msg.content, "OpenAI: content should match");

        // Test Anthropic adapter round-trip
        let anthropic = AnthropicAdapter::new("test-key".to_string());
        let provider_format = anthropic.translate_to_provider(&msg);
        let restored = anthropic.translate_from_provider(&provider_format);
        prop_assert!(restored.is_some(), "Anthropic: translation back should succeed");
        let restored = restored.unwrap();
        prop_assert_eq!(&restored.role, &msg.role, "Anthropic: role should match");
        prop_assert_eq!(&restored.content, &msg.content, "Anthropic: content should match");

        // Test Local adapter round-trip
        let local = LocalLlmAdapter::new("http://localhost:11434".to_string(), "llama3".to_string());
        let provider_format = local.translate_to_provider(&msg);
        let restored = local.translate_from_provider(&provider_format);
        prop_assert!(restored.is_some(), "Local: translation back should succeed");
        let restored = restored.unwrap();
        prop_assert_eq!(&restored.role, &msg.role, "Local: role should match");
        prop_assert_eq!(&restored.content, &msg.content, "Local: content should match");
    }
}
