//! Ordered, bounded user content with unchanged legacy text serialization.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{ConnectorError, ProviderId};

pub const MAX_CONTENT_PARTS: usize = 32;
pub const MAX_IMAGES_PER_MESSAGE: usize = 4;
pub const MAX_IMAGE_BYTES: usize = 1024 * 1024;
pub const MAX_IMAGE_DIMENSION: u32 = 2048;
pub const MAX_MESSAGE_CONTENT_BYTES: usize = 6 * 1024 * 1024;

fn invalid() -> String { "invalid or oversized message content".into() }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageMediaType {
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
}

impl ImageMediaType {
    pub fn as_str(self) -> &'static str {
        match self { Self::Png => "image/png", Self::Jpeg => "image/jpeg" }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ImageWire", into = "ImageWire")]
pub struct ImageInput {
    media_type: ImageMediaType,
    data: String,
    width: u32,
    height: u32,
    decoded_bytes: usize,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageWire { media_type: ImageMediaType, data: String }

impl TryFrom<ImageWire> for ImageInput {
    type Error = String;
    fn try_from(value: ImageWire) -> Result<Self, Self::Error> {
        Self::new(value.media_type, value.data)
    }
}

impl From<ImageInput> for ImageWire {
    fn from(value: ImageInput) -> Self { Self { media_type: value.media_type, data: value.data } }
}

impl std::fmt::Debug for ImageInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ImageInput").field("media_type", &self.media_type)
            .field("dimensions", &(self.width, self.height)).field("decoded_bytes", &self.decoded_bytes)
            .field("data", &"[REDACTED]").finish()
    }
}

fn png_dimensions(bytes: &[u8]) -> Result<(u32, u32), String> {
    if bytes.len() < 45 || &bytes[..8] != b"\x89PNG\r\n\x1a\n"
        || &bytes[8..12] != 13u32.to_be_bytes().as_slice() || &bytes[12..16] != b"IHDR"
    { return Err(invalid()); }
    let width = u32::from_be_bytes(bytes[16..20].try_into().map_err(|_| invalid())?);
    let height = u32::from_be_bytes(bytes[20..24].try_into().map_err(|_| invalid())?);
    let mut offset = 8usize;
    let mut saw_data = false;
    let mut saw_end = false;
    while offset < bytes.len() {
        let header = bytes.get(offset..offset.saturating_add(8)).ok_or_else(invalid)?;
        let length = u32::from_be_bytes(header[..4].try_into().map_err(|_| invalid())?) as usize;
        let end = offset.checked_add(12).and_then(|n| n.checked_add(length)).ok_or_else(invalid)?;
        if end > bytes.len() { return Err(invalid()); }
        let kind = &header[4..8];
        if kind == b"acTL" || kind == b"fcTL" || kind == b"fdAT" { return Err(invalid()); }
        if kind == b"IDAT" { saw_data = true; }
        if kind == b"IEND" {
            if length != 0 || end != bytes.len() { return Err(invalid()); }
            saw_end = true;
        }
        offset = end;
    }
    if !saw_data || !saw_end { return Err(invalid()); }
    Ok((width, height))
}

fn jpeg_dimensions(bytes: &[u8]) -> Result<(u32, u32), String> {
    if bytes.len() < 12 || !bytes.starts_with(&[0xff, 0xd8]) || !bytes.ends_with(&[0xff, 0xd9]) {
        return Err(invalid());
    }
    let mut offset = 2usize;
    let mut dimensions = None;
    while offset < bytes.len().saturating_sub(2) {
        if bytes[offset] != 0xff { return Err(invalid()); }
        while bytes.get(offset) == Some(&0xff) { offset += 1; }
        let marker = *bytes.get(offset).ok_or_else(invalid)?;
        offset += 1;
        if marker == 0xd9 { break; }
        if marker == 0x00 || marker == 0xd8 || (0xd0..=0xd7).contains(&marker) { return Err(invalid()); }
        let size_bytes = bytes.get(offset..offset.saturating_add(2)).ok_or_else(invalid)?;
        let size = u16::from_be_bytes(size_bytes.try_into().map_err(|_| invalid())?) as usize;
        if size < 2 || offset.saturating_add(size) > bytes.len() { return Err(invalid()); }
        if matches!(marker, 0xc0 | 0xc1 | 0xc2) {
            if size < 8 || dimensions.is_some() { return Err(invalid()); }
            let height = u16::from_be_bytes(bytes[offset+3..offset+5].try_into().map_err(|_| invalid())?) as u32;
            let width = u16::from_be_bytes(bytes[offset+5..offset+7].try_into().map_err(|_| invalid())?) as u32;
            dimensions = Some((width, height));
        }
        if marker == 0xda { return dimensions.ok_or_else(invalid); }
        offset += size;
    }
    Err(invalid())
}

impl ImageInput {
    /// Accept only explicit PNG/JPEG containers with bounded bytes/dimensions.
    /// No URL fetch, filesystem access, raster decoding or animation occurs.
    pub fn new(media_type: ImageMediaType, data: String) -> Result<Self, String> {
        if data.is_empty() || data.len() > MAX_IMAGE_BYTES.div_ceil(3) * 4 { return Err(invalid()); }
        let bytes = base64::engine::general_purpose::STANDARD.decode(&data).map_err(|_| invalid())?;
        if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES { return Err(invalid()); }
        let (width, height) = match media_type { ImageMediaType::Png => png_dimensions(&bytes)?, ImageMediaType::Jpeg => jpeg_dimensions(&bytes)? };
        if width == 0 || height == 0 || width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION { return Err(invalid()); }
        Ok(Self { media_type, data, width, height, decoded_bytes: bytes.len() })
    }
    pub fn media_type(&self) -> ImageMediaType { self.media_type }
    pub fn base64_data(&self) -> &str { &self.data }
    pub fn dimensions(&self) -> (u32, u32) { (self.width, self.height) }
    pub fn decoded_bytes(&self) -> usize { self.decoded_bytes }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", try_from = "PartWire")]
pub enum ContentPart {
    Text { text: String },
    Image { #[serde(flatten)] image: ImageInput },
    /// Reserved protocol tag. No adapter accepts audio in this contract.
    Audio,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum PartWire {
    Text { text: String },
    Image { media_type: ImageMediaType, data: String },
    Audio,
}

impl TryFrom<PartWire> for ContentPart {
    type Error = String;
    fn try_from(value: PartWire) -> Result<Self, Self::Error> {
        Ok(match value {
            PartWire::Text { text } => Self::Text { text },
            PartWire::Image { media_type, data } => Self::Image { image: ImageInput::new(media_type, data)? },
            PartWire::Audio => Self::Audio,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, try_from = "ContentWire")]
pub enum MessageContent { Text(String), Parts(Vec<ContentPart>) }

#[derive(Deserialize)]
#[serde(untagged)]
enum ContentWire { Text(String), Parts(Vec<ContentPart>) }

impl TryFrom<ContentWire> for MessageContent {
    type Error = String;
    fn try_from(value: ContentWire) -> Result<Self, Self::Error> {
        match value {
            ContentWire::Text(text) => Ok(Self::Text(text)),
            ContentWire::Parts(parts) => Self::parts(parts),
        }
    }
}

impl MessageContent {
    pub fn parts(parts: Vec<ContentPart>) -> Result<Self, String> {
        if parts.is_empty() || parts.len() > MAX_CONTENT_PARTS
            || parts.iter().filter(|part| matches!(part, ContentPart::Image { .. })).count() > MAX_IMAGES_PER_MESSAGE
            || serde_json::to_vec(&parts).map_or(true, |bytes| bytes.len() > MAX_MESSAGE_CONTENT_BYTES)
        { return Err(invalid()); }
        Ok(Self::Parts(parts))
    }
    pub fn images(&self) -> impl Iterator<Item = &ImageInput> {
        let parts = match self { Self::Text(_) => &[][..], Self::Parts(parts) => parts.as_slice() };
        parts.iter().filter_map(|part| match part { ContentPart::Image { image } => Some(image), _ => None })
    }
    pub fn has_audio(&self) -> bool { matches!(self, Self::Parts(parts) if parts.iter().any(|part| matches!(part, ContentPart::Audio))) }
    pub fn is_multimodal(&self) -> bool { self.has_audio() || self.images().next().is_some() }
    pub fn text_only(&self, provider: &str) -> Result<String, ConnectorError> {
        if self.is_multimodal() { return Err(ConnectorError::unsupported_content(provider.into())); }
        Ok(self.text_projection())
    }
    /// A safe transcript/search/debug projection. Encoded bytes never appear.
    pub fn text_projection(&self) -> String {
        match self {
            Self::Text(text) => text.clone(),
            Self::Parts(parts) => parts.iter().map(|part| match part {
                ContentPart::Text { text } => text.clone(),
                ContentPart::Image { image } => format!("[image {} {}x{}]", image.media_type.as_str(), image.width, image.height),
                ContentPart::Audio => "[unsupported audio]".into(),
            }).collect::<Vec<_>>().join(""),
        }
    }
    pub fn is_empty(&self) -> bool { matches!(self, Self::Text(text) if text.is_empty()) }
    pub fn contains(&self, pattern: &str) -> bool { self.text_projection().contains(pattern) }
    pub fn starts_with(&self, pattern: &str) -> bool { self.text_projection().starts_with(pattern) }
    pub fn serialized_bytes(&self) -> usize { serde_json::to_vec(self).map_or(usize::MAX, |bytes| bytes.len()) }
    /// Physical legacy text bytes or complete multipart serialized bytes.
    pub fn len(&self) -> usize { match self { Self::Text(text) => text.len(), Self::Parts(_) => self.serialized_bytes() } }
    pub fn legacy_text(&self) -> Option<&str> { match self { Self::Text(text) => Some(text), Self::Parts(_) => None } }
}

impl std::fmt::Debug for MessageContent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str(&self.text_projection()) }
}
impl std::fmt::Display for MessageContent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str(&self.text_projection()) }
}
impl From<String> for MessageContent { fn from(value: String) -> Self { Self::Text(value) } }
impl From<&str> for MessageContent { fn from(value: &str) -> Self { Self::Text(value.into()) } }
impl PartialEq<str> for MessageContent { fn eq(&self, other: &str) -> bool { matches!(self, Self::Text(text) if text == other) } }
impl PartialEq<&str> for MessageContent { fn eq(&self, other: &&str) -> bool { self == *other } }
impl PartialEq<String> for MessageContent { fn eq(&self, other: &String) -> bool { self == other.as_str() } }
impl PartialEq<MessageContent> for String { fn eq(&self, other: &MessageContent) -> bool { other == self } }

/// Explicit operator declaration for one configured model/deployment. The
/// token allowance is a conservative input bound, never a measured price.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageInputProfile { pub model_id: String, pub max_tokens_per_image: u32 }

impl ImageInputProfile {
    pub fn validate(&self, model: &str) -> Result<(), ConnectorError> {
        if self.model_id != model || model.is_empty() || model.len() > 256
            || self.max_tokens_per_image == 0 || self.max_tokens_per_image > 1_000_000 {
            return Err(ConnectorError::ProtocolError("invalid image input accounting profile".into()));
        }
        Ok(())
    }
    pub fn token_bound(&self, model: &str, messages: &[crate::connector::StandardMessage]) -> Result<u32, ConnectorError> {
        self.validate(model)?;
        let count = messages.iter().map(|message| message.content.images().count()).sum::<usize>();
        let count = u32::try_from(count).map_err(|_| ConnectorError::ProtocolError(invalid()))?;
        count.checked_mul(self.max_tokens_per_image).ok_or_else(|| ConnectorError::ProtocolError("image input accounting overflow".into()))
    }
}

pub fn reject_unsupported(messages: &[crate::connector::StandardMessage], provider: &ProviderId) -> Result<(), ConnectorError> {
    if messages.iter().any(|message| message.content.is_multimodal()) { return Err(ConnectorError::unsupported_content(provider.clone())); }
    Ok(())
}

pub fn validate_messages(messages: &[crate::connector::StandardMessage], provider: &ProviderId, profile: Option<&ImageInputProfile>) -> Result<u32, ConnectorError> {
    for message in messages {
        if let MessageContent::Parts(parts) = &message.content { MessageContent::parts(parts.clone()).map_err(ConnectorError::ProtocolError)?; }
        if message.content.has_audio() || (message.content.is_multimodal() && message.role != "user") {
            return Err(ConnectorError::unsupported_content(provider.clone()));
        }
    }
    if !messages.iter().any(|message| message.content.is_multimodal()) { return Ok(0); }
    let profile = profile.ok_or_else(|| ConnectorError::unsupported_content(provider.clone()))?;
    profile.token_bound(&profile.model_id, messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

    fn image_content() -> MessageContent {
        MessageContent::parts(vec![ContentPart::Text { text: "describe".into() },
            ContentPart::Image { image: ImageInput::new(ImageMediaType::Png, PNG.into()).unwrap() }]).unwrap()
    }

    #[test]
    fn image_input_legacy_string_json_and_projection_remain_exact() {
        let text: MessageContent = serde_json::from_str(r#""legacy \u03bb""#).unwrap();
        assert_eq!(text, "legacy λ");
        assert_eq!(serde_json::to_string(&text).unwrap(), "\"legacy λ\"");
        let legacy: crate::connector::StandardMessage = serde_json::from_str(r#"{"role":"user","content":"hello"}"#).unwrap();
        assert_eq!(legacy.content, "hello");
        assert_eq!(serde_json::to_value(&legacy).unwrap(), serde_json::json!({"role":"user","content":"hello"}));
    }

    #[test]
    fn image_input_validated_parts_roundtrip_and_redact_all_debug_projections() {
        let content = image_content();
        let encoded = serde_json::to_string(&content).unwrap();
        assert!(encoded.contains(PNG));
        assert_eq!(serde_json::from_str::<MessageContent>(&encoded).unwrap(), content);
        assert!(!format!("{content:?}").contains(PNG));
        assert!(!content.text_projection().contains(PNG));
        assert!(content.text_projection().contains("1x1"));
        let message = crate::connector::StandardMessage::user_content(content);
        assert!(!format!("{message:?}").contains(PNG));
    }

    #[test]
    fn image_input_rejects_unknown_media_bad_base64_container_counts_and_dimensions() {
        for media in ["image/gif", "image/webp", "image/svg+xml", "application/octet-stream"] {
            let value = serde_json::json!([{"type":"image","media_type":media,"data":PNG}]);
            assert!(serde_json::from_value::<MessageContent>(value).is_err());
        }
        assert!(ImageInput::new(ImageMediaType::Jpeg, PNG.into()).is_err());
        assert!(ImageInput::new(ImageMediaType::Png, "secret-invalid-base64".into()).is_err());
        assert!(ImageInput::new(ImageMediaType::Png, "x".repeat(MAX_IMAGE_BYTES.div_ceil(3)*4+1)).is_err());
        let mut bytes = base64::engine::general_purpose::STANDARD.decode(PNG).unwrap();
        bytes[16..20].copy_from_slice(&(MAX_IMAGE_DIMENSION+1).to_be_bytes());
        assert!(ImageInput::new(ImageMediaType::Png, base64::engine::general_purpose::STANDARD.encode(bytes)).is_err());
        assert!(MessageContent::parts(vec![]).is_err());
        assert!(MessageContent::parts(vec![ContentPart::Text { text: "x".into() }; MAX_CONTENT_PARTS+1]).is_err());
        let image = ImageInput::new(ImageMediaType::Png, PNG.into()).unwrap();
        assert!(MessageContent::parts(vec![ContentPart::Image { image }; MAX_IMAGES_PER_MESSAGE+1]).is_err());
    }

    #[test]
    fn image_input_unknown_profiles_audio_and_non_user_images_fail_closed() {
        let message = crate::connector::StandardMessage::user_content(image_content());
        let provider = "fixture".to_string();
        assert!(matches!(validate_messages(std::slice::from_ref(&message), &provider, None), Err(ConnectorError::UnsupportedContent(_))));
        let profile = ImageInputProfile { model_id: "image-fixture".into(), max_tokens_per_image: 3000 };
        assert_eq!(validate_messages(std::slice::from_ref(&message), &provider, Some(&profile)).unwrap(), 3000);
        assert!(profile.validate("another-model").is_err());
        let audio = crate::connector::StandardMessage::user_content(MessageContent::parts(vec![ContentPart::Audio]).unwrap());
        assert!(matches!(validate_messages(&[audio], &provider, Some(&profile)), Err(ConnectorError::UnsupportedContent(_))));
        let mut assistant = message; assistant.role = "assistant".into();
        assert!(matches!(validate_messages(&[assistant], &provider, Some(&profile)), Err(ConnectorError::UnsupportedContent(_))));
    }

    proptest::proptest! {
        #[test]
        fn image_input_untrusted_base64_never_panics_or_echoes_data(data in ".{0,2048}") {
            if let Err(error) = ImageInput::new(ImageMediaType::Png, data) {
                proptest::prop_assert_eq!(error, "invalid or oversized message content");
            }
        }
    }
}
