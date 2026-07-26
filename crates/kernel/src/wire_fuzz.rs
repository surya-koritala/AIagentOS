//! Internal harness for exercising the production transport decoder with
//! libFuzzer-generated fragmentation and ordering plans.

use crate::mcp_server::JsonRpcRequest;
use crate::syscall_server::{Syscall, SyscallReply};
use crate::wire_io::{BoundedLineDecoder, DecodeStep};

const MAX_FUZZ_FRAME_BYTES: usize = 4096;
const MAX_FRAGMENT_WIDTH: usize = 128;
const MAX_FRAGMENT_CONTROLS: usize = 32;

/// Exercise actual newline framing with ordered, reversed, rotated, or
/// pair-swapped fragments.
///
/// The first four input bytes select the frame bound, ordering mode, and number
/// of fragment-width controls. Remaining bytes are untrusted transport data.
/// Assertions are deliberately limited to invariants every byte stream must
/// satisfy: no panic and no retained/allocation capacity beyond the selected
/// frame bound. Syntactically complete frames are also passed through all
/// public raw/MCP envelope deserializers.
pub fn exercise_fragmented_transport(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let max_bytes = 1 + usize::from(u16::from_le_bytes([data[0], data[1]])) % MAX_FUZZ_FRAME_BYTES;
    let reorder_mode = data[2] % 4;
    let available_controls = data.len().saturating_sub(4);
    let control_count = (1 + usize::from(data[3]) % MAX_FRAGMENT_CONTROLS).min(available_controls);
    if control_count == 0 {
        return;
    }

    let controls = &data[4..4 + control_count];
    let payload = &data[4 + control_count..];
    let mut fragments = fragment(payload, controls);
    reorder(&mut fragments, reorder_mode, data[0]);
    decode_and_parse(&fragments, max_bytes);
}

fn fragment<'a>(payload: &'a [u8], controls: &[u8]) -> Vec<&'a [u8]> {
    let mut fragments = Vec::new();
    let mut offset = 0;
    let mut control_index = 0;
    while offset < payload.len() {
        let width = 1 + usize::from(controls[control_index % controls.len()]) % MAX_FRAGMENT_WIDTH;
        let end = offset.saturating_add(width).min(payload.len());
        fragments.push(&payload[offset..end]);
        offset = end;
        control_index += 1;
    }
    fragments
}

fn reorder(fragments: &mut [&[u8]], mode: u8, rotation_seed: u8) {
    match mode {
        1 => fragments.reverse(),
        2 if !fragments.is_empty() => {
            let fragment_count = fragments.len();
            fragments.rotate_left(usize::from(rotation_seed) % fragment_count);
        }
        3 => {
            for pair in fragments.chunks_exact_mut(2) {
                pair.swap(0, 1);
            }
        }
        _ => {}
    }
}

fn decode_and_parse(fragments: &[&[u8]], max_bytes: usize) {
    let mut decoder = BoundedLineDecoder::new(max_bytes);
    let mut rejected = false;

    'fragments: for fragment in fragments {
        let mut offset = 0;
        while offset < fragment.len() {
            let step = decoder.feed(&fragment[offset..]);
            assert_decoder_bound(&decoder, max_bytes);
            match step {
                DecodeStep::Pending { consumed } => {
                    assert!(consumed > 0);
                    offset += consumed;
                }
                DecodeStep::Complete { consumed, line } => {
                    assert!(consumed > 0);
                    offset += consumed;
                    match line {
                        Ok(line) => parse_public_envelopes(line.as_bytes()),
                        Err(_) => {
                            rejected = true;
                            break 'fragments;
                        }
                    }
                    decoder = BoundedLineDecoder::new(max_bytes);
                    assert_decoder_bound(&decoder, max_bytes);
                }
            }
        }
    }

    if !rejected {
        assert_decoder_bound(&decoder, max_bytes);
        if let Ok(Some(line)) = decoder.finish_eof() {
            parse_public_envelopes(line.as_bytes());
        }
    }
}

fn assert_decoder_bound(decoder: &BoundedLineDecoder, max_bytes: usize) {
    assert!(decoder.retained_bytes() <= max_bytes);
    assert!(decoder.peak_retained_bytes() <= max_bytes);
    assert!(decoder.allocated_capacity() <= max_bytes);
    assert!(decoder.peak_allocated_capacity() <= max_bytes);
}

fn parse_public_envelopes(frame: &[u8]) {
    let _ = serde_json::from_slice::<Syscall>(frame);
    let _ = serde_json::from_slice::<SyscallReply>(frame);
    let _ = serde_json::from_slice::<JsonRpcRequest>(frame);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_covers_every_fragment_order_without_panicking() {
        for mode in 0..4 {
            let mut input = vec![32, 0, mode, 3, 1, 2, 3];
            input.extend_from_slice(b"{\"op\":\"ping\"}\n{\"status\":\"pong\"}\n");
            exercise_fragmented_transport(&input);
        }
    }
}
