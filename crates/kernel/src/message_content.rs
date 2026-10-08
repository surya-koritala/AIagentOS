//! Ordered, bounded user content with unchanged legacy text serialization.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{ConnectorError, ProviderId};

pub const MAX_CONTENT_PARTS: usize = 32;
pub const MAX_IMAGES_PER_MESSAGE: usize = 4;
pub const MAX_IMAGE_BYTES: usize = 1024 * 1024;
pub const MAX_IMAGE_DIMENSION: u32 = 2048;
pub const MAX_MESSAGE_CONTENT_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_IMAGES_PER_REQUEST: usize = 16;
pub const MAX_IMAGE_BYTES_PER_REQUEST: usize = 4 * 1024 * 1024;
pub const MAX_IMAGE_REQUEST_BYTES: usize = 8 * 1024 * 1024;

fn invalid() -> String {
    "invalid or oversized message content".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageMediaType {
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
}

impl ImageMediaType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
        }
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
struct ImageWire {
    media_type: ImageMediaType,
    data: String,
}

impl TryFrom<ImageWire> for ImageInput {
    type Error = String;
    fn try_from(value: ImageWire) -> Result<Self, Self::Error> {
        Self::new(value.media_type, value.data)
    }
}

impl From<ImageInput> for ImageWire {
    fn from(value: ImageInput) -> Self {
        Self {
            media_type: value.media_type,
            data: value.data,
        }
    }
}

impl std::fmt::Debug for ImageInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImageInput")
            .field("media_type", &self.media_type)
            .field("dimensions", &(self.width, self.height))
            .field("decoded_bytes", &self.decoded_bytes)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

fn png_crc(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn png_dimensions(bytes: &[u8]) -> Result<(u32, u32), String> {
    if bytes.len() < 45 || !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(invalid());
    }
    let mut offset = 8usize;
    let mut dimensions = None;
    let mut color = 0u8;
    let mut depth = 0u8;
    let mut palette = false;
    let mut data_started = false;
    let mut data_bytes = 0usize;
    let mut data_ended = false;
    while offset < bytes.len() {
        let header = bytes
            .get(offset..offset.saturating_add(8))
            .ok_or_else(invalid)?;
        let length = u32::from_be_bytes(header[..4].try_into().map_err(|_| invalid())?) as usize;
        let end = offset
            .checked_add(12)
            .and_then(|n| n.checked_add(length))
            .ok_or_else(invalid)?;
        let chunk = bytes
            .get(offset + 8..end.saturating_sub(4))
            .ok_or_else(invalid)?;
        let expected = u32::from_be_bytes(
            bytes
                .get(end.saturating_sub(4)..end)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        );
        let kind = &header[4..8];
        if !kind.iter().all(u8::is_ascii_alphabetic)
            || !kind[2].is_ascii_uppercase()
            || png_crc(&bytes[offset + 4..end - 4]) != expected
        {
            return Err(invalid());
        }
        if dimensions.is_none() && kind != b"IHDR" {
            return Err(invalid());
        }
        match kind {
            b"IHDR" => {
                if dimensions.is_some() || length != 13 {
                    return Err(invalid());
                }
                depth = chunk[8];
                color = chunk[9];
                let legal_depth = match color {
                    0 => matches!(depth, 1 | 2 | 4 | 8 | 16),
                    2 | 4 | 6 => matches!(depth, 8 | 16),
                    3 => matches!(depth, 1 | 2 | 4 | 8),
                    _ => false,
                };
                if !legal_depth || chunk[10] != 0 || chunk[11] != 0 || chunk[12] > 1 {
                    return Err(invalid());
                }
                dimensions = Some((
                    u32::from_be_bytes(chunk[..4].try_into().map_err(|_| invalid())?),
                    u32::from_be_bytes(chunk[4..8].try_into().map_err(|_| invalid())?),
                ));
            }
            b"PLTE" => {
                if palette
                    || data_started
                    || data_ended
                    || matches!(color, 0 | 4)
                    || length == 0
                    || !length.is_multiple_of(3)
                    || length > 768
                    || (color == 3 && length / 3 > 1usize << depth)
                {
                    return Err(invalid());
                }
                palette = true;
            }
            b"IDAT" => {
                if data_ended || (color == 3 && !palette) {
                    return Err(invalid());
                }
                data_started = true;
                data_bytes = data_bytes.checked_add(length).ok_or_else(invalid)?;
            }
            b"IEND" => {
                if length != 0 || end != bytes.len() || data_bytes == 0 {
                    return Err(invalid());
                }
                return dimensions.ok_or_else(invalid);
            }
            b"acTL" | b"fcTL" | b"fdAT" => return Err(invalid()),
            _ => {
                if kind[0].is_ascii_uppercase() {
                    return Err(invalid());
                }
                if data_started {
                    data_ended = true;
                }
            }
        }
        offset = end;
    }
    Err(invalid())
}

// Validate the bounded interchange container, not compressed raster samples.
// Only 8-bit Huffman sequential/progressive DCT with up to four components is
// accepted; arithmetic, lossless, hierarchical and deferred-height modes fail.
fn jpeg_dimensions(bytes: &[u8]) -> Result<(u32, u32), String> {
    if !bytes.starts_with(&[0xff, 0xd8]) {
        return Err(invalid());
    }
    let mut offset = 2usize;
    let mut dimensions = None;
    let mut frame_marker = 0;
    let mut components = Vec::<(u8, u8, u8)>::new();
    let mut quantization = [false; 4];
    let mut huffman = [[false; 4]; 2];
    let mut restart_interval = 0u16;
    let mut scans = 0usize;
    while offset < bytes.len() {
        if bytes[offset] != 0xff {
            return Err(invalid());
        }
        while bytes.get(offset) == Some(&0xff) {
            offset += 1;
        }
        let marker = *bytes.get(offset).ok_or_else(invalid)?;
        offset += 1;
        if marker == 0xd9 {
            if scans == 0 || offset != bytes.len() {
                return Err(invalid());
            }
            return dimensions.ok_or_else(invalid);
        }
        let size_bytes = bytes
            .get(offset..offset.saturating_add(2))
            .ok_or_else(invalid)?;
        let size = usize::from(u16::from_be_bytes(
            size_bytes.try_into().map_err(|_| invalid())?,
        ));
        if size < 2 {
            return Err(invalid());
        }
        let end = offset.checked_add(size).ok_or_else(invalid)?;
        let segment = bytes.get(offset + 2..end).ok_or_else(invalid)?;
        match marker {
            0xc0..=0xc2 => {
                if dimensions.is_some() || segment.len() < 6 || segment[0] != 8 {
                    return Err(invalid());
                }
                let count = usize::from(segment[5]);
                if !(1..=4).contains(&count) || segment.len() != 6 + 3 * count {
                    return Err(invalid());
                }
                for component in segment[6..].chunks_exact(3) {
                    if components.iter().any(|(id, _, _)| *id == component[0])
                        || !(1..=4).contains(&(component[1] >> 4))
                        || !(1..=4).contains(&(component[1] & 15))
                        || component[2] > 3
                    {
                        return Err(invalid());
                    }
                    components.push((component[0], component[1], component[2]));
                }
                frame_marker = marker;
                dimensions = Some((
                    u32::from(u16::from_be_bytes(
                        segment[3..5].try_into().map_err(|_| invalid())?,
                    )),
                    u32::from(u16::from_be_bytes(
                        segment[1..3].try_into().map_err(|_| invalid())?,
                    )),
                ));
            }
            0xdb => {
                let mut position = 0usize;
                while position < segment.len() {
                    let selector = segment[position];
                    position += 1;
                    if selector >> 4 > 1 || selector & 15 > 3 {
                        return Err(invalid());
                    }
                    let size = if selector >> 4 == 0 { 64 } else { 128 };
                    let table = segment.get(position..position + size).ok_or_else(invalid)?;
                    if (size == 64 && table.contains(&0))
                        || (size == 128 && table.chunks_exact(2).any(|value| value == [0, 0]))
                    {
                        return Err(invalid());
                    }
                    quantization[usize::from(selector & 15)] = true;
                    position += size;
                }
                if segment.is_empty() {
                    return Err(invalid());
                }
            }
            0xc4 => {
                let mut position = 0usize;
                while position < segment.len() {
                    let header = segment.get(position..position + 17).ok_or_else(invalid)?;
                    if header[0] >> 4 > 1 || header[0] & 15 > 3 {
                        return Err(invalid());
                    }
                    let count = header[1..]
                        .iter()
                        .map(|count| usize::from(*count))
                        .sum::<usize>();
                    let mut remaining = 1i32;
                    for count in &header[1..] {
                        remaining = remaining * 2 - i32::from(*count);
                        if remaining < 0 {
                            return Err(invalid());
                        }
                    }
                    if count == 0
                        || count > 256
                        || segment.get(position + 17..position + 17 + count).is_none()
                    {
                        return Err(invalid());
                    }
                    huffman[usize::from(header[0] >> 4)][usize::from(header[0] & 15)] = true;
                    position += 17 + count;
                }
                if segment.is_empty() {
                    return Err(invalid());
                }
            }
            0xdd if segment.len() == 2 => {
                restart_interval = u16::from_be_bytes(segment.try_into().map_err(|_| invalid())?);
            }
            0xda => {
                if dimensions.is_none() || segment.len() < 4 {
                    return Err(invalid());
                }
                let count = usize::from(segment[0]);
                if count == 0 || count > components.len() || segment.len() != 4 + 2 * count {
                    return Err(invalid());
                }
                let start = segment[1 + 2 * count];
                let finish = segment[2 + 2 * count];
                let approximation = segment[3 + 2 * count];
                if frame_marker == 0xc2 {
                    if start > finish
                        || finish > 63
                        || (start == 0 && finish != 0)
                        || (start != 0 && count != 1)
                        || approximation >> 4 > 13
                        || approximation & 15 > 13
                        || (approximation >> 4 != 0
                            && approximation >> 4 != (approximation & 15) + 1)
                    {
                        return Err(invalid());
                    }
                } else if start != 0 || finish != 63 || approximation != 0 {
                    return Err(invalid());
                }
                let mut selected = Vec::new();
                let mut sampling = 0u16;
                for component in segment[1..1 + 2 * count].chunks_exact(2) {
                    let (index, (_, sample, table)) = components
                        .iter()
                        .enumerate()
                        .find(|(_, value)| value.0 == component[0])
                        .ok_or_else(invalid)?;
                    if selected.last().is_some_and(|previous| *previous >= index)
                        || component[1] >> 4 > 3
                        || component[1] & 15 > 3
                        || !quantization[usize::from(*table)]
                        || (start == 0
                            && approximation >> 4 == 0
                            && !huffman[0][usize::from(component[1] >> 4)])
                        || (finish != 0 && !huffman[1][usize::from(component[1] & 15)])
                    {
                        return Err(invalid());
                    }
                    selected.push(index);
                    sampling += u16::from(sample >> 4) * u16::from(sample & 15);
                }
                if count > 1 && sampling > 10 {
                    return Err(invalid());
                }
                scans += 1;
                if scans > 256 {
                    return Err(invalid());
                }
                offset = end;
                let mut entropy_bytes = 0usize;
                let mut restart = 0u8;
                while offset < bytes.len() {
                    if bytes[offset] != 0xff {
                        entropy_bytes += 1;
                        offset += 1;
                        continue;
                    }
                    let next = *bytes.get(offset + 1).ok_or_else(invalid)?;
                    if next == 0 {
                        entropy_bytes += 1;
                        offset += 2;
                    } else if (0xd0..=0xd7).contains(&next) {
                        if restart_interval == 0 || next != 0xd0 + restart {
                            return Err(invalid());
                        }
                        restart = (restart + 1) % 8;
                        offset += 2;
                    } else {
                        break;
                    }
                }
                if entropy_bytes == 0 {
                    return Err(invalid());
                }
                continue;
            }
            0xe0..=0xef | 0xfe => {}
            _ => return Err(invalid()),
        }
        offset = end;
    }
    Err(invalid())
}

impl ImageInput {
    pub fn from_bytes(media_type: ImageMediaType, bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
            return Err(invalid());
        }
        Self::new(
            media_type,
            base64::engine::general_purpose::STANDARD.encode(bytes),
        )
    }
    /// Accept only explicit PNG/JPEG containers with bounded bytes/dimensions.
    /// No URL fetch, filesystem access, raster decoding or animation occurs.
    pub fn new(media_type: ImageMediaType, data: String) -> Result<Self, String> {
        if data.is_empty() || data.len() > MAX_IMAGE_BYTES.div_ceil(3) * 4 {
            return Err(invalid());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&data)
            .map_err(|_| invalid())?;
        if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
            return Err(invalid());
        }
        let (width, height) = match media_type {
            ImageMediaType::Png => png_dimensions(&bytes)?,
            ImageMediaType::Jpeg => jpeg_dimensions(&bytes)?,
        };
        if width == 0 || height == 0 || width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION
        {
            return Err(invalid());
        }
        Ok(Self {
            media_type,
            data,
            width,
            height,
            decoded_bytes: bytes.len(),
        })
    }
    pub fn media_type(&self) -> ImageMediaType {
        self.media_type
    }
    pub fn base64_data(&self) -> &str {
        &self.data
    }
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }
    pub fn decoded_bytes(&self) -> usize {
        self.decoded_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", try_from = "PartWire")]
pub enum ContentPart {
    Text {
        text: String,
    },
    Image {
        #[serde(flatten)]
        image: ImageInput,
    },
    /// Reserved protocol tag. No adapter accepts audio in this contract.
    Audio,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum PartWire {
    Text {
        text: String,
    },
    Image {
        media_type: ImageMediaType,
        data: String,
    },
    Audio,
}

impl TryFrom<PartWire> for ContentPart {
    type Error = String;
    fn try_from(value: PartWire) -> Result<Self, Self::Error> {
        Ok(match value {
            PartWire::Text { text } => Self::Text { text },
            PartWire::Image { media_type, data } => Self::Image {
                image: ImageInput::new(media_type, data)?,
            },
            PartWire::Audio => Self::Audio,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, try_from = "ContentWire")]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ContentWire {
    Text(String),
    Parts(Vec<ContentPart>),
}

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
        if parts.is_empty()
            || parts.len() > MAX_CONTENT_PARTS
            || parts
                .iter()
                .filter(|part| matches!(part, ContentPart::Image { .. }))
                .count()
                > MAX_IMAGES_PER_MESSAGE
            || serde_json::to_vec(&parts)
                .map_or(true, |bytes| bytes.len() > MAX_MESSAGE_CONTENT_BYTES)
        {
            return Err(invalid());
        }
        Ok(Self::Parts(parts))
    }
    pub fn images(&self) -> impl Iterator<Item = &ImageInput> {
        let parts = match self {
            Self::Text(_) => &[][..],
            Self::Parts(parts) => parts.as_slice(),
        };
        parts.iter().filter_map(|part| match part {
            ContentPart::Image { image } => Some(image),
            _ => None,
        })
    }
    pub fn has_audio(&self) -> bool {
        matches!(self, Self::Parts(parts) if parts.iter().any(|part| matches!(part, ContentPart::Audio)))
    }
    pub fn is_multimodal(&self) -> bool {
        self.has_audio() || self.images().next().is_some()
    }
    pub fn text_only(&self, provider: &str) -> Result<String, ConnectorError> {
        if self.is_multimodal() {
            return Err(ConnectorError::unsupported_content(provider.into()));
        }
        Ok(self.text_projection())
    }
    /// A safe transcript/search/debug projection. Encoded bytes never appear.
    pub fn text_projection(&self) -> String {
        match self {
            Self::Text(text) => text.clone(),
            Self::Parts(parts) => parts
                .iter()
                .map(|part| match part {
                    ContentPart::Text { text } => text.clone(),
                    ContentPart::Image { image } => format!(
                        "[image {} {}x{}]",
                        image.media_type.as_str(),
                        image.width,
                        image.height
                    ),
                    ContentPart::Audio => "[unsupported audio]".into(),
                })
                .collect::<Vec<_>>()
                .join(""),
        }
    }
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Text(text) if text.is_empty())
    }
    pub fn contains(&self, pattern: &str) -> bool {
        self.text_projection().contains(pattern)
    }
    pub fn starts_with(&self, pattern: &str) -> bool {
        self.text_projection().starts_with(pattern)
    }
    pub fn serialized_bytes(&self) -> usize {
        serde_json::to_vec(self).map_or(usize::MAX, |bytes| bytes.len())
    }
    /// Physical legacy text bytes or complete multipart serialized bytes.
    pub fn len(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Parts(_) => self.serialized_bytes(),
        }
    }
    pub fn legacy_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Parts(_) => None,
        }
    }
}

impl std::fmt::Debug for MessageContent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.text_projection())
    }
}
impl std::fmt::Display for MessageContent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.text_projection())
    }
}
impl From<String> for MessageContent {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}
impl From<&str> for MessageContent {
    fn from(value: &str) -> Self {
        Self::Text(value.into())
    }
}
impl PartialEq<str> for MessageContent {
    fn eq(&self, other: &str) -> bool {
        matches!(self, Self::Text(text) if text == other)
    }
}
impl PartialEq<&str> for MessageContent {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}
impl PartialEq<String> for MessageContent {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}
impl PartialEq<MessageContent> for String {
    fn eq(&self, other: &MessageContent) -> bool {
        other == self
    }
}

/// Explicit operator declaration for one configured model/deployment. The
/// token allowance is a conservative input bound, never a measured price.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageInputProfile {
    pub model_id: String,
    pub max_tokens_per_image: u32,
}

impl ImageInputProfile {
    pub fn validate(&self, model: &str) -> Result<(), ConnectorError> {
        if self.model_id != model
            || model.is_empty()
            || model.len() > 256
            || self.max_tokens_per_image == 0
            || self.max_tokens_per_image > 1_000_000
        {
            return Err(ConnectorError::ProtocolError(
                "invalid image input accounting profile".into(),
            ));
        }
        Ok(())
    }
    pub fn token_bound(
        &self,
        model: &str,
        messages: &[crate::connector::StandardMessage],
    ) -> Result<u32, ConnectorError> {
        self.validate(model)?;
        let count = messages
            .iter()
            .map(|message| message.content.images().count())
            .sum::<usize>();
        let count = u32::try_from(count).map_err(|_| ConnectorError::ProtocolError(invalid()))?;
        count
            .checked_mul(self.max_tokens_per_image)
            .ok_or_else(|| ConnectorError::ProtocolError("image input accounting overflow".into()))
    }
}

pub fn reject_unsupported(
    messages: &[crate::connector::StandardMessage],
    provider: &ProviderId,
) -> Result<(), ConnectorError> {
    validate_messages(messages, provider, None)?;
    Ok(())
}

pub fn validate_messages(
    messages: &[crate::connector::StandardMessage],
    provider: &ProviderId,
    profile: Option<&ImageInputProfile>,
) -> Result<u32, ConnectorError> {
    let mut image_count = 0usize;
    let mut image_bytes = 0usize;
    for message in messages {
        if let MessageContent::Parts(parts) = &message.content {
            MessageContent::parts(parts.clone()).map_err(ConnectorError::ProtocolError)?;
        }
        if message.content.has_audio()
            || (matches!(message.content, MessageContent::Parts(_)) && message.role != "user")
        {
            return Err(ConnectorError::unsupported_content(provider.clone()));
        }
        for image in message.content.images() {
            image_count = image_count.saturating_add(1);
            image_bytes = image_bytes.saturating_add(image.decoded_bytes());
        }
    }
    if !messages
        .iter()
        .any(|message| message.content.is_multimodal())
    {
        return Ok(0);
    }
    if image_count > MAX_IMAGES_PER_REQUEST
        || image_bytes > MAX_IMAGE_BYTES_PER_REQUEST
        || serde_json::to_vec(messages).map_or(true, |bytes| bytes.len() > MAX_IMAGE_REQUEST_BYTES)
    {
        return Err(ConnectorError::ProtocolError(invalid()));
    }
    let profile = profile.ok_or_else(|| ConnectorError::unsupported_content(provider.clone()))?;
    profile.token_bound(&profile.model_id, messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC";

    fn image_content() -> MessageContent {
        MessageContent::parts(vec![
            ContentPart::Text {
                text: "describe".into(),
            },
            ContentPart::Image {
                image: ImageInput::new(ImageMediaType::Png, PNG.into()).unwrap(),
            },
        ])
        .unwrap()
    }

    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut result = (data.len() as u32).to_be_bytes().to_vec();
        result.extend_from_slice(kind);
        result.extend_from_slice(data);
        result.extend_from_slice(&png_crc(&result[4..]).to_be_bytes());
        result
    }

    fn jpeg_fixture() -> Vec<u8> {
        let mut bytes = vec![0xff, 0xd8];
        let mut segment = |marker: u8, data: &[u8]| {
            bytes.extend_from_slice(&[0xff, marker]);
            bytes.extend_from_slice(&((data.len() + 2) as u16).to_be_bytes());
            bytes.extend_from_slice(data);
        };
        let mut quantization = vec![0];
        quantization.extend_from_slice(&[1; 64]);
        segment(0xdb, &quantization);
        segment(0xc0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]);
        let mut huffman = vec![0, 1];
        huffman.extend_from_slice(&[0; 15]);
        huffman.push(0);
        huffman.extend_from_slice(&[0x10, 1]);
        huffman.extend_from_slice(&[0; 15]);
        huffman.push(0);
        segment(0xc4, &huffman);
        segment(0xda, &[1, 1, 0, 0, 63, 0]);
        bytes.extend_from_slice(&[0x3f, 0xff, 0xd9]);
        bytes
    }

    #[test]
    fn image_input_png_checks_crc_ihdr_palette_and_critical_order() {
        let original = base64::engine::general_purpose::STANDARD
            .decode(PNG)
            .unwrap();
        assert_eq!(png_crc(b"IEND"), 0xae42_6082);
        let mut corrupted = original.clone();
        corrupted[29] ^= 1;
        assert!(png_dimensions(&corrupted).is_err());
        for (index, value) in [(8, 3), (9, 1), (10, 1), (11, 1), (12, 2)] {
            let mut header = original[16..29].to_vec();
            header[index] = value;
            let mut bytes = original[..8].to_vec();
            bytes.extend(png_chunk(b"IHDR", &header));
            bytes.extend_from_slice(&original[33..]);
            assert!(
                png_dimensions(&bytes).is_err(),
                "invalid IHDR field {index}"
            );
        }
        let mut indexed_header = original[16..29].to_vec();
        indexed_header[8] = 1;
        indexed_header[9] = 3;
        let mut indexed = original[..8].to_vec();
        indexed.extend(png_chunk(b"IHDR", &indexed_header));
        indexed.extend_from_slice(&original[33..]);
        assert!(png_dimensions(&indexed).is_err());
        for extra in [
            png_chunk(b"IHDR", &original[16..29]),
            png_chunk(b"PLTE", &[1, 2]),
            png_chunk(b"ABCD", &[]),
            png_chunk(b"acTL", &[0; 8]),
        ] {
            let mut bytes = original[..33].to_vec();
            bytes.extend(extra);
            bytes.extend_from_slice(&original[33..]);
            assert!(png_dimensions(&bytes).is_err());
        }
        let mut split = original[..original.len() - 12].to_vec();
        split.extend(png_chunk(b"tEXt", b"key\0value"));
        split.extend(png_chunk(b"IDAT", &[]));
        split.extend_from_slice(&original[original.len() - 12..]);
        assert!(png_dimensions(&split).is_err());
    }

    #[test]
    fn image_input_jpeg_requires_complete_sof_sos_tables_and_entropy_framing() {
        let original = jpeg_fixture();
        let image = ImageInput::new(
            ImageMediaType::Jpeg,
            base64::engine::general_purpose::STANDARD.encode(&original),
        )
        .unwrap();
        assert_eq!(image.dimensions(), (1, 1));
        let frame = original
            .windows(2)
            .position(|value| value == [0xff, 0xc0])
            .unwrap();
        let scan = original
            .windows(2)
            .position(|value| value == [0xff, 0xda])
            .unwrap();
        for (index, value) in [
            (frame + 4, 12),
            (frame + 9, 2),
            (frame + 11, 0),
            (frame + 12, 4),
            (scan + 4, 2),
            (scan + 5, 9),
            (scan + 6, 0x44),
            (scan + 7, 1),
            (scan + 9, 1),
        ] {
            let mut bytes = original.clone();
            bytes[index] = value;
            assert!(
                jpeg_dimensions(&bytes).is_err(),
                "invalid JPEG field {index}"
            );
        }
        let mut truncated = original.clone();
        truncated.truncate(scan + 10);
        truncated.extend_from_slice(&[0xff, 0xd9]);
        assert!(jpeg_dimensions(&truncated).is_err());
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(jpeg_dimensions(&trailing).is_err());
        let mut restart = original.clone();
        restart.splice(original.len() - 2..original.len() - 2, [0xff, 0xd0]);
        assert!(jpeg_dimensions(&restart).is_err());
        assert!(jpeg_dimensions(&[
            0xff, 0xd8, 0xff, 0xc0, 0, 8, 8, 0, 1, 0, 1, 0, 0xff, 0xda, 0, 2, 0xff, 0xd9
        ])
        .is_err());
    }

    #[test]
    fn image_input_legacy_string_json_and_projection_remain_exact() {
        let text: MessageContent = serde_json::from_str(r#""legacy \u03bb""#).unwrap();
        assert_eq!(text, "legacy λ");
        assert_eq!(serde_json::to_string(&text).unwrap(), "\"legacy λ\"");
        let legacy: crate::connector::StandardMessage =
            serde_json::from_str(r#"{"role":"user","content":"hello"}"#).unwrap();
        assert_eq!(legacy.content, "hello");
        assert_eq!(
            serde_json::to_value(&legacy).unwrap(),
            serde_json::json!({"role":"user","content":"hello"})
        );
    }

    #[test]
    fn image_input_validated_parts_roundtrip_and_redact_all_debug_projections() {
        let content = image_content();
        let encoded = serde_json::to_string(&content).unwrap();
        assert!(encoded.contains(PNG));
        assert_eq!(
            serde_json::from_str::<MessageContent>(&encoded).unwrap(),
            content
        );
        assert!(!format!("{content:?}").contains(PNG));
        assert!(!content.text_projection().contains(PNG));
        assert!(content.text_projection().contains("1x1"));
        let message = crate::connector::StandardMessage::user_content(content);
        assert!(!format!("{message:?}").contains(PNG));
    }

    #[test]
    fn image_input_rejects_unknown_media_bad_base64_container_counts_and_dimensions() {
        for media in [
            "image/gif",
            "image/webp",
            "image/svg+xml",
            "application/octet-stream",
        ] {
            let value = serde_json::json!([{"type":"image","media_type":media,"data":PNG}]);
            assert!(serde_json::from_value::<MessageContent>(value).is_err());
        }
        assert!(ImageInput::new(ImageMediaType::Jpeg, PNG.into()).is_err());
        assert!(ImageInput::new(ImageMediaType::Png, "secret-invalid-base64".into()).is_err());
        assert!(ImageInput::new(
            ImageMediaType::Png,
            "x".repeat(MAX_IMAGE_BYTES.div_ceil(3) * 4 + 1)
        )
        .is_err());
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(PNG)
            .unwrap();
        bytes[16..20].copy_from_slice(&(MAX_IMAGE_DIMENSION + 1).to_be_bytes());
        let crc = png_crc(&bytes[12..29]);
        bytes[29..33].copy_from_slice(&crc.to_be_bytes());
        assert!(ImageInput::new(
            ImageMediaType::Png,
            base64::engine::general_purpose::STANDARD.encode(bytes)
        )
        .is_err());
        assert!(MessageContent::parts(vec![]).is_err());
        assert!(MessageContent::parts(vec![
            ContentPart::Text { text: "x".into() };
            MAX_CONTENT_PARTS + 1
        ])
        .is_err());
        let image = ImageInput::new(ImageMediaType::Png, PNG.into()).unwrap();
        assert!(MessageContent::parts(vec![
            ContentPart::Image { image };
            MAX_IMAGES_PER_MESSAGE + 1
        ])
        .is_err());
    }

    #[test]
    fn image_input_unknown_profiles_audio_and_non_user_images_fail_closed() {
        let message = crate::connector::StandardMessage::user_content(image_content());
        let provider = "fixture".to_string();
        assert!(matches!(
            validate_messages(std::slice::from_ref(&message), &provider, None),
            Err(ConnectorError::UnsupportedContent(_))
        ));
        let profile = ImageInputProfile {
            model_id: "image-fixture".into(),
            max_tokens_per_image: 3000,
        };
        assert_eq!(
            validate_messages(std::slice::from_ref(&message), &provider, Some(&profile)).unwrap(),
            3000
        );
        assert!(profile.validate("another-model").is_err());
        assert!(validate_messages(
            &vec![message.clone(); MAX_IMAGES_PER_REQUEST + 1],
            &provider,
            Some(&profile)
        )
        .is_err());
        let audio = crate::connector::StandardMessage::user_content(
            MessageContent::parts(vec![ContentPart::Audio]).unwrap(),
        );
        assert!(matches!(
            validate_messages(&[audio], &provider, Some(&profile)),
            Err(ConnectorError::UnsupportedContent(_))
        ));
        let mut assistant = message;
        assistant.role = "assistant".into();
        assert!(matches!(
            validate_messages(&[assistant], &provider, Some(&profile)),
            Err(ConnectorError::UnsupportedContent(_))
        ));
    }

    proptest::proptest! {
        #[test]
        fn image_input_untrusted_base64_never_panics_or_echoes_data(data in ".{0,2048}") {
            if let Err(error) = ImageInput::new(ImageMediaType::Png, data) {
                proptest::prop_assert_eq!(error, "invalid or oversized message content");
            }
        }

        #[test]
        fn image_input_random_containers_remain_bounded_and_redacted(bytes in proptest::collection::vec(proptest::num::u8::ANY,0..2048)) {
            for media in [ImageMediaType::Png,ImageMediaType::Jpeg] {
                if let Err(error) = ImageInput::new(media,base64::engine::general_purpose::STANDARD.encode(&bytes)) {
                    proptest::prop_assert_eq!(error,"invalid or oversized message content");
                }
            }
        }
    }
}
