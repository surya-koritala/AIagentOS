//! Vision support — send images to vision-capable LLMs.

use crate::connector::{StandardMessage, LlmSession, LlmResponse, ToolDefinition};
use crate::ConnectorError;

/// Encode an image file as a base64 data URL for vision models.
pub fn image_to_data_url(path: &str) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("Can't read image: {}", e))?;
    let mime = if path.ends_with(".png") { "image/png" }
        else if path.ends_with(".jpg") || path.ends_with(".jpeg") { "image/jpeg" }
        else if path.ends_with(".gif") { "image/gif" }
        else if path.ends_with(".webp") { "image/webp" }
        else { "image/png" };
    let b64 = base64_encode(&bytes);
    Ok(format!("data:{};base64,{}", mime, b64))
}

/// Create a vision message with text + image.
pub fn vision_message(text: &str, image_path: &str) -> Result<serde_json::Value, String> {
    let data_url = image_to_data_url(image_path)?;
    Ok(serde_json::json!({
        "role": "user",
        "content": [
            {"type": "text", "text": text},
            {"type": "image_url", "image_url": {"url": data_url}}
        ]
    }))
}

/// Create a vision message from raw bytes.
pub fn vision_message_from_bytes(text: &str, bytes: &[u8], mime: &str) -> serde_json::Value {
    let b64 = base64_encode(bytes);
    serde_json::json!({
        "role": "user",
        "content": [
            {"type": "text", "text": text},
            {"type": "image_url", "image_url": {"url": format!("data:{};base64,{}", mime, b64)}}
        ]
    })
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        output.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        output.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 { output.push(TABLE[((triple >> 6) & 0x3F) as usize] as char); } else { output.push('='); }
        if chunk.len() > 2 { output.push(TABLE[(triple & 0x3F) as usize] as char); } else { output.push('='); }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_works() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b"ab"), "YWI=");
    }

    #[test]
    fn image_data_url_format() {
        // Create a tiny test PNG
        let path = "/tmp/test_vision.png";
        std::fs::write(path, &[0x89, 0x50, 0x4E, 0x47]).unwrap(); // PNG magic bytes
        let url = image_to_data_url(path).unwrap();
        assert!(url.starts_with("data:image/png;base64,"));
        std::fs::remove_file(path).ok();
    }
}
