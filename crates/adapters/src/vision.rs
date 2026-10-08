//! Inline-image translation and explicit operator-owned model admission bounds.

use kernel::connector::{ContentPart, ImageInputProfile, MessageContent, StandardMessage};
use kernel::ConnectorError;
use serde_json::{json, Value};

pub(crate) fn preflight(provider: &str, model: &str, profile: Option<&ImageInputProfile>, messages: &[StandardMessage]) -> Result<u32, ConnectorError> {
    if let Some(profile) = profile { profile.validate(model)?; }
    kernel::message_content::validate_messages(messages, &provider.to_string(), profile)
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
        MessageContent::Parts(parts) => json!(parts.iter().map(|part| match part {
            ContentPart::Text { text } => json!({"text":text}),
            ContentPart::Image { image } => json!({"inlineData":{
                "mimeType":image.media_type().as_str(),"data":image.base64_data()
            }}),
            ContentPart::Audio => json!({"unsupportedAudio":{}}),
        }).collect::<Vec<_>>()),
    }
}
