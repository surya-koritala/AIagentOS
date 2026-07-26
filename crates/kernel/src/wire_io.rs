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

/// Maximum queued provider/executor events at each streaming boundary.
pub const STREAM_EVENT_BUFFER_CAPACITY: usize = 64;

/// Maximum time allowed for the first frame on a connection.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Maximum idle time between complete frames on an established connection.
pub const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Recommended maximum interval between application-level keepalive probes.
///
/// This is deliberately half the default idle timeout so one delayed probe
/// does not immediately turn a healthy but quiet connection into an idle close.
pub const RECOMMENDED_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(150);

/// Maximum time a client waits for peer EOF after half-closing its write side.
pub const GRACEFUL_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum wall-clock duration of one wire or MCP request.
///
/// Provider turns have their own 120-second timeout. This outer deadline leaves
/// a small cleanup window while bounding all other dispatch paths as well.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(130);

/// One incremental decoding step over a caller-provided transport fragment.
#[derive(Debug)]
pub(crate) enum DecodeStep {
    /// The fragment was consumed but did not finish a frame.
    Pending { consumed: usize },
    /// The fragment finished or rejected a frame.
    Complete {
        consumed: usize,
        line: std::io::Result<String>,
    },
}

/// Incremental newline-frame decoder shared by the production reader, property
/// tests, and the transport fuzz harness.
///
/// Only bytes belonging to the current frame are retained. The size check runs
/// before allocation or copying, so even a very large offered fragment cannot
/// make retained input exceed `max_bytes`.
#[derive(Debug)]
pub(crate) struct BoundedLineDecoder {
    frame: Vec<u8>,
    max_bytes: usize,
    #[cfg(any(test, feature = "fuzzing"))]
    peak_retained_bytes: usize,
    #[cfg(any(test, feature = "fuzzing"))]
    peak_allocated_capacity: usize,
}

impl BoundedLineDecoder {
    pub(crate) fn new(max_bytes: usize) -> Self {
        let frame = Vec::with_capacity(max_bytes.min(8 * 1024));
        #[cfg(any(test, feature = "fuzzing"))]
        let peak_allocated_capacity = frame.capacity();
        Self {
            frame,
            max_bytes,
            #[cfg(any(test, feature = "fuzzing"))]
            peak_retained_bytes: 0,
            #[cfg(any(test, feature = "fuzzing"))]
            peak_allocated_capacity,
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn retained_bytes(&self) -> usize {
        self.frame.len()
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn peak_retained_bytes(&self) -> usize {
        self.peak_retained_bytes
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn allocated_capacity(&self) -> usize {
        self.frame.capacity()
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn peak_allocated_capacity(&self) -> usize {
        self.peak_allocated_capacity
    }

    /// Consume at most one newline-terminated frame from `input`.
    ///
    /// The caller retains any bytes after `consumed` for the next decoder.
    pub(crate) fn feed(&mut self, input: &[u8]) -> DecodeStep {
        debug_assert!(!input.is_empty());
        let newline = input.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(input.len(), |position| position + 1);
        let payload_len = newline.unwrap_or(input.len());
        let required = self.frame.len().saturating_add(payload_len);

        if required > self.max_bytes {
            return DecodeStep::Complete {
                consumed,
                line: Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("JSON frame exceeds {} bytes", self.max_bytes),
                )),
            };
        }

        if required > self.frame.capacity() {
            if let Err(error) = self.frame.try_reserve_exact(payload_len) {
                return DecodeStep::Complete {
                    consumed,
                    line: Err(std::io::Error::other(format!(
                        "unable to reserve bounded JSON frame storage: {error}"
                    ))),
                };
            }
        }
        #[cfg(any(test, feature = "fuzzing"))]
        {
            self.peak_allocated_capacity = self.peak_allocated_capacity.max(self.frame.capacity());
        }
        self.frame.extend_from_slice(&input[..payload_len]);
        #[cfg(any(test, feature = "fuzzing"))]
        {
            self.peak_retained_bytes = self.peak_retained_bytes.max(self.frame.len());
        }
        debug_assert!(self.frame.len() <= self.max_bytes);

        if newline.is_some() {
            DecodeStep::Complete {
                consumed,
                line: self.finish_frame(),
            }
        } else {
            DecodeStep::Pending { consumed }
        }
    }

    pub(crate) fn finish_eof(mut self) -> std::io::Result<Option<String>> {
        if self.frame.is_empty() {
            Ok(None)
        } else {
            self.finish_frame().map(Some)
        }
    }

    fn finish_frame(&mut self) -> std::io::Result<String> {
        if self.frame.last() == Some(&b'\r') {
            self.frame.pop();
        }
        String::from_utf8(std::mem::take(&mut self.frame))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame is not UTF-8"))
    }
}

/// Read one newline-delimited UTF-8 frame without ever buffering more than
/// `max_bytes`. The returned string excludes the newline and optional CR.
pub async fn read_bounded_line<R>(
    reader: &mut BufReader<R>,
    max_bytes: usize,
) -> std::io::Result<Option<String>>
where
    R: AsyncRead + Unpin,
{
    let mut decoder = BoundedLineDecoder::new(max_bytes);
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return decoder.finish_eof();
        }
        match decoder.feed(available) {
            DecodeStep::Pending { consumed } => reader.consume(consumed),
            DecodeStep::Complete { consumed, line } => {
                reader.consume(consumed);
                return line.map(Some);
            }
        }
    }
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

/// Half-close a framed client's write side and require bounded peer EOF.
///
/// Callers must have consumed the reply (or terminal stream frame) for every
/// request before entering this handshake. Receiving another frame after the
/// half-close is therefore a protocol-state error rather than data to discard.
pub async fn graceful_close_framed<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    max_bytes: usize,
    timeout: std::time::Duration,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    writer.shutdown().await?;
    let peer = tokio::time::timeout(timeout, read_bounded_line(reader, max_bytes))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "peer did not finish graceful close before the deadline",
            )
        })??;
    match peer {
        None => Ok(()),
        Some(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "peer sent an unexpected frame during graceful close",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tokio::io::AsyncReadExt;

    type DecodedFrame = Result<String, std::io::ErrorKind>;

    fn fragment_bytes(input: &[u8], widths: &[usize]) -> Vec<Vec<u8>> {
        let mut fragments = Vec::new();
        let mut offset = 0;
        let mut width_index = 0;
        while offset < input.len() {
            let width = widths
                .get(width_index % widths.len().max(1))
                .copied()
                .unwrap_or(1)
                .max(1);
            let end = offset.saturating_add(width).min(input.len());
            fragments.push(input[offset..end].to_vec());
            offset = end;
            width_index += 1;
        }
        fragments
    }

    fn decode_fragments(
        fragments: &[Vec<u8>],
        max_bytes: usize,
    ) -> (Vec<DecodedFrame>, usize, usize) {
        let mut frames = Vec::new();
        let mut decoder = BoundedLineDecoder::new(max_bytes);
        let mut peak_retained = 0;
        let mut peak_capacity = decoder.allocated_capacity();
        let mut rejected = false;

        'fragments: for fragment in fragments {
            let mut offset = 0;
            while offset < fragment.len() {
                let step = decoder.feed(&fragment[offset..]);
                peak_retained = peak_retained.max(decoder.peak_retained_bytes());
                peak_capacity = peak_capacity.max(decoder.peak_allocated_capacity());
                assert!(decoder.retained_bytes() <= max_bytes);
                assert!(decoder.peak_retained_bytes() <= max_bytes);
                assert!(decoder.peak_allocated_capacity() <= max_bytes);
                match step {
                    DecodeStep::Pending { consumed } => {
                        assert!(consumed > 0);
                        offset += consumed;
                    }
                    DecodeStep::Complete { consumed, line } => {
                        assert!(consumed > 0);
                        offset += consumed;
                        let decoded = line.map_err(|error| error.kind());
                        rejected = decoded.is_err();
                        frames.push(decoded);
                        if rejected {
                            break 'fragments;
                        }
                        decoder = BoundedLineDecoder::new(max_bytes);
                        peak_capacity = peak_capacity.max(decoder.peak_allocated_capacity());
                    }
                }
            }
        }

        if !rejected {
            peak_retained = peak_retained.max(decoder.peak_retained_bytes());
            peak_capacity = peak_capacity.max(decoder.peak_allocated_capacity());
            match decoder.finish_eof() {
                Ok(Some(line)) => frames.push(Ok(line)),
                Ok(None) => {}
                Err(error) => frames.push(Err(error.kind())),
            }
        }
        (frames, peak_retained, peak_capacity)
    }

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
    async fn bounded_reader_reassembles_one_byte_fragments_and_preserves_following_frames() {
        let mut reader = BufReader::with_capacity(1, &b"{\"op\":\"ping\"}\nnext\n"[..]);
        assert_eq!(
            read_bounded_line(&mut reader, 64).await.unwrap().as_deref(),
            Some("{\"op\":\"ping\"}")
        );
        assert_eq!(
            read_bounded_line(&mut reader, 64).await.unwrap().as_deref(),
            Some("next")
        );
        assert!(read_bounded_line(&mut reader, 64).await.unwrap().is_none());
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

    #[test]
    fn oversized_offered_fragment_does_not_amplify_decoder_memory() {
        let max_bytes = 1024;
        let offered = vec![b'x'; 1024 * 1024];
        let mut decoder = BoundedLineDecoder::new(max_bytes);

        let DecodeStep::Complete { line, .. } = decoder.feed(&offered) else {
            panic!("one-megabyte fragment must exceed the one-kilobyte frame bound");
        };
        assert_eq!(
            line.expect_err("oversized frame").kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(decoder.retained_bytes(), 0);
        assert_eq!(decoder.peak_retained_bytes(), 0);
        assert!(decoder.allocated_capacity() <= max_bytes);
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 512,
            .. ProptestConfig::default()
        })]

        #[test]
        fn arbitrary_partial_reads_match_monolithic_decoding(
            payload in proptest::collection::vec(
                any::<u8>().prop_filter("payload byte is not a frame delimiter", |byte| *byte != b'\n'),
                0..2048,
            ),
            widths in proptest::collection::vec(1usize..128, 1..32),
            max_bytes in 0usize..1024,
        ) {
            let mut terminated = payload;
            terminated.push(b'\n');
            let fragmented = fragment_bytes(&terminated, &widths);
            let monolithic = vec![terminated];

            let (expected, expected_peak, expected_capacity) =
                decode_fragments(&monolithic, max_bytes);
            let (actual, actual_peak, actual_capacity) =
                decode_fragments(&fragmented, max_bytes);

            prop_assert_eq!(actual, expected);
            prop_assert!(actual_peak <= max_bytes);
            prop_assert!(expected_peak <= max_bytes);
            prop_assert!(actual_capacity <= max_bytes);
            prop_assert!(expected_capacity <= max_bytes);
        }

        #[test]
        fn shuffled_transport_fragments_never_panic_or_exceed_the_frame_bound(
            input in proptest::collection::vec(any::<u8>(), 0..4096),
            widths in proptest::collection::vec(1usize..128, 1..32),
            max_bytes in 0usize..1024,
            reorder_mode in 0u8..4,
            rotation in any::<usize>(),
        ) {
            let mut fragments = fragment_bytes(&input, &widths);
            match reorder_mode {
                1 => fragments.reverse(),
                2 if !fragments.is_empty() => {
                    let fragment_count = fragments.len();
                    fragments.rotate_left(rotation % fragment_count);
                }
                3 => {
                    for pair in fragments.chunks_exact_mut(2) {
                        pair.swap(0, 1);
                    }
                }
                _ => {}
            }

            let (_, peak_retained, peak_capacity) =
                decode_fragments(&fragments, max_bytes);
            prop_assert!(peak_retained <= max_bytes);
            prop_assert!(peak_capacity <= max_bytes);
        }
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

    #[tokio::test]
    async fn graceful_close_half_closes_and_confirms_peer_eof() {
        let (client, mut peer) = tokio::io::duplex(64);
        let (read, mut write) = tokio::io::split(client);
        let mut reader = BufReader::new(read);
        let peer_task = tokio::spawn(async move {
            let mut input = Vec::new();
            peer.read_to_end(&mut input).await.unwrap();
            assert!(input.is_empty());
            peer.shutdown().await.unwrap();
        });

        graceful_close_framed(
            &mut reader,
            &mut write,
            64,
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        peer_task.await.unwrap();
    }

    #[tokio::test]
    async fn graceful_close_rejects_an_unread_peer_frame() {
        let (client, mut peer) = tokio::io::duplex(64);
        let (read, mut write) = tokio::io::split(client);
        let mut reader = BufReader::new(read);
        let peer_task = tokio::spawn(async move {
            let mut input = Vec::new();
            peer.read_to_end(&mut input).await.unwrap();
            peer.write_all(b"unexpected\n").await.unwrap();
            peer.shutdown().await.unwrap();
        });

        let error = graceful_close_framed(
            &mut reader,
            &mut write,
            64,
            std::time::Duration::from_secs(1),
        )
        .await
        .expect_err("unread frame must fail close");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        peer_task.await.unwrap();
    }
}
