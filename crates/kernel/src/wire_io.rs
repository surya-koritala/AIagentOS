//! Shared bounded newline-JSON transport helpers.
//!
//! The public syscall and loopback MCP servers deliberately use a simple
//! newline-delimited JSON framing contract. Tokio's `Lines` adapter does not
//! impose a maximum line length, so using it directly at an untrusted boundary
//! permits memory amplification before serde gets a chance to reject a frame.
//! This module keeps both protocols on one bounded implementation.

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Maximum serialized request or response frame.
///
/// Signed package archives may contain up to 16 MiB of binary data and are
/// hex-encoded on this JSON protocol. The additional MiB covers the operation
/// envelope and leaves all other calls with a deterministic upper bound.
pub const MAX_JSON_FRAME_BYTES: usize = crate::package::MAX_ARCHIVE_BYTES * 2 + 1024 * 1024;

/// Default maximum number of simultaneously admitted transport connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Maximum time allowed for the first frame on a connection.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Maximum idle time between complete frames on an established connection.
pub const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Maximum wall-clock duration of one wire or MCP request.
///
/// Provider turns have their own 120-second timeout. This outer deadline leaves
/// a small cleanup window while bounding all other dispatch paths as well.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(130);

/// Read one newline-delimited UTF-8 frame without ever buffering more than
/// `max_bytes`. The returned string excludes the newline and optional CR.
pub async fn read_bounded_line<R>(
    reader: &mut BufReader<R>,
    max_bytes: usize,
) -> std::io::Result<Option<String>>
where
    R: AsyncRead + Unpin,
{
    let mut frame = Vec::with_capacity(max_bytes.min(8 * 1024));
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if frame.is_empty() {
                return Ok(None);
            }
            break;
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        let payload = newline.unwrap_or(available.len());
        if frame.len().saturating_add(payload) > max_bytes {
            reader.consume(consumed);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("JSON frame exceeds {max_bytes} bytes"),
            ));
        }
        frame.extend_from_slice(&available[..payload]);
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }

    if frame.last() == Some(&b'\r') {
        frame.pop();
    }
    String::from_utf8(frame)
        .map(Some)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame is not UTF-8"))
}

/// Serialize and write exactly one bounded newline-delimited JSON frame.
pub async fn write_bounded_json<W, T>(
    writer: &mut W,
    value: &T,
    max_bytes: usize,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let payload = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    if payload.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("JSON frame exceeds {max_bytes} bytes"),
        ));
    }
    writer.write_all(&payload).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_reader_accepts_crlf_and_eof_terminated_frames() {
        let mut crlf = BufReader::new(&b"{\"ok\":true}\r\n"[..]);
        assert_eq!(
            read_bounded_line(&mut crlf, 64).await.unwrap().as_deref(),
            Some("{\"ok\":true}")
        );

        let mut eof = BufReader::new(&b"last-frame"[..]);
        assert_eq!(
            read_bounded_line(&mut eof, 64).await.unwrap().as_deref(),
            Some("last-frame")
        );
        assert!(read_bounded_line(&mut eof, 64).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn bounded_reader_rejects_oversized_and_invalid_utf8_frames() {
        let mut oversized = BufReader::new(&b"12345\n"[..]);
        let error = read_bounded_line(&mut oversized, 4)
            .await
            .expect_err("oversized");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        let mut invalid = BufReader::new(&b"\xff\n"[..]);
        let error = read_bounded_line(&mut invalid, 4)
            .await
            .expect_err("invalid UTF-8");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn bounded_writer_rejects_oversized_json() {
        let mut output = Vec::new();
        write_bounded_json(&mut output, &serde_json::json!({"ok": true}), 64)
            .await
            .unwrap();
        assert_eq!(output, b"{\"ok\":true}\n");

        let error = write_bounded_json(&mut output, &"oversized", 4)
            .await
            .expect_err("oversized");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
