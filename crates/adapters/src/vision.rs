//! Inline-image translation and explicit operator-owned model admission bounds.

use kernel::connector::{ContentPart, ImageInputProfile, MessageContent, StandardMessage};
use kernel::ConnectorError;
use serde_json::{json, Value};

pub(crate) fn preflight(
    provider: &str,
    model: &str,
    profile: Option<&ImageInputProfile>,
    messages: &[StandardMessage],
) -> Result<u32, ConnectorError> {
    if let Some(profile) = profile {
        profile.validate(model)?;
    }
    kernel::message_content::validate_messages(messages, &provider.to_string(), profile)
}

/// Vendor diagnostics and request IDs can echo an image under arbitrary JSON
/// keys. Preserve the typed class and retry hint, never their untrusted text.
pub(crate) fn protect_error(
    mut error: ConnectorError,
    messages: &[StandardMessage],
) -> ConnectorError {
    if !messages
        .iter()
        .any(|message| message.content.images().next().is_some())
    {
        return error;
    }
    match &mut error {
        ConnectorError::Authentication(context)
        | ConnectorError::Authorization(context)
        | ConnectorError::ServiceUnavailable(context)
        | ConnectorError::InvalidRequest(context)
        | ConnectorError::ToolIncompatiblePrimary(context)
        | ConnectorError::UnsupportedContent(context)
        | ConnectorError::ContentFiltered(context)
        | ConnectorError::Timeout(context)
        | ConnectorError::Cancelled(context) => {
            context.message = "image request failed; provider diagnostic redacted".into();
            context.request_id = None;
        }
        ConnectorError::RateLimited(rate) => {
            rate.context.message =
                "image request rate limited; provider diagnostic redacted".into();
            rate.context.request_id = None;
        }
        ConnectorError::ConnectionFailed(detail)
        | ConnectorError::ProtocolError(detail)
        | ConnectorError::StreamError(detail)
        | ConnectorError::PartialStream(detail) => {
            *detail = "image request failed; provider diagnostic redacted".into();
        }
        ConnectorError::ProviderUnavailable(_) => {}
    }
    error
}

pub(crate) fn openai_content(content: &MessageContent) -> Value {
    match content {
        MessageContent::Text(text) => json!(text),
        MessageContent::Parts(parts) => json!(parts.iter().map(|part| match part {
            ContentPart::Text { text } => json!({"type":"text","text":text}),
            ContentPart::Image { image } => json!({"type":"image_url","image_url":{
                "url":format!("data:{};base64,{}", image.media_type().as_str(), image.base64_data()), "detail":"high"
            }}),
            // Preflight rejects this tag. Keep it explicit, never erase it.
            ContentPart::Audio => json!({"type":"audio"}),
        }).collect::<Vec<_>>()),
    }
}

pub(crate) fn anthropic_content(content: &MessageContent) -> Value {
    match content {
        MessageContent::Text(text) => json!(text),
        MessageContent::Parts(parts) => json!(parts.iter().map(|part| match part {
            ContentPart::Text { text } => json!({"type":"text","text":text}),
            ContentPart::Image { image } => json!({"type":"image","source":{
                "type":"base64","media_type":image.media_type().as_str(),"data":image.base64_data()
            }}),
            ContentPart::Audio => json!({"type":"audio"}),
        }).collect::<Vec<_>>()),
    }
}

pub(crate) fn gemini_parts(content: &MessageContent) -> Value {
    match content {
        MessageContent::Text(text) => json!([{"text":text}]),
        MessageContent::Parts(parts) => json!(parts
            .iter()
            .map(|part| match part {
                ContentPart::Text { text } => json!({"text":text}),
                ContentPart::Image { image } => json!({"inlineData":{
                    "mimeType":image.media_type().as_str(),"data":image.base64_data()
                }}),
                ContentPart::Audio => json!({"unsupportedAudio":{}}),
            })
            .collect::<Vec<_>>()),
    }
}
