//! Same-run loopback comparison; protocol correctness is gated, timings reported.

use super::{read_bounded_line, write_bounded_json};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const FRAME_LIMIT: usize = 2048;
const WARMUP: usize = 8;
const SAMPLES: usize = 128;

async fn write_trial_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &Value,
    split: bool,
) -> std::io::Result<()> {
    if !split {
        return write_bounded_json(writer, value, FRAME_LIMIT).await;
    }
    // Exact pre-change writer, including the same limit and flush contract.
    let payload = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    if payload.len() > FRAME_LIMIT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame bound",
        ));
    }
    writer.write_all(&payload).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

async fn trial(split: bool, ordinal: usize) -> Value {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        socket.set_nodelay(false).unwrap();
        assert!(!socket.nodelay().unwrap());
        let (read, mut write) = socket.into_split();
        let mut reader = BufReader::new(read);
        for _ in 0..WARMUP + SAMPLES {
            let frame = read_bounded_line(&mut reader, FRAME_LIMIT)
                .await
                .unwrap()
                .unwrap();
            let value: Value = serde_json::from_str(&frame).unwrap();
            write_trial_frame(&mut write, &value, split).await.unwrap();
        }
    });
    let socket = TcpStream::connect(address).await.unwrap();
    socket.set_nodelay(false).unwrap();
    assert!(!socket.nodelay().unwrap());
    let (read, mut write) = socket.into_split();
    let mut reader = BufReader::new(read);
    let mut elapsed_us = Vec::with_capacity(SAMPLES);
    let mut bytes = 0usize;
    for sequence in 0..WARMUP + SAMPLES {
        let expected = json!({"sequence": sequence, "payload": "bounded loopback λ".repeat(4)});
        let started = Instant::now();
        write_trial_frame(&mut write, &expected, split)
            .await
            .unwrap();
        let frame = read_bounded_line(&mut reader, FRAME_LIMIT)
            .await
            .unwrap()
            .unwrap();
        let actual: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(
            actual, expected,
            "framing must preserve sequence and Unicode bytes"
        );
        if sequence >= WARMUP {
            elapsed_us.push(started.elapsed().as_micros());
            bytes += frame.len();
        }
    }
    peer.await.unwrap();
    let total: u128 = elapsed_us.iter().sum();
    elapsed_us.sort_unstable();
    json!({
        "trial": ordinal,
        "mode": if split { "baseline_split" } else { "coalesced" },
        "samples": SAMPLES,
        "payload_bytes": bytes,
        "total_us": total,
        "p50_us": elapsed_us[SAMPLES / 2],
        "p95_us": elapsed_us[SAMPLES * 95 / 100],
        "socket_nodelay": false,
        "real_provider_calls": false,
    })
}

#[tokio::test]
async fn same_run_loopback_frame_latency_preserves_protocol() {
    let measurements = tokio::time::timeout(Duration::from_secs(120), async {
        let mut measurements = Vec::new();
        // Reverse the order in the second pair to retain runner/order effects.
        for (ordinal, split) in [true, false, false, true].into_iter().enumerate() {
            measurements.push(trial(split, ordinal).await);
        }
        measurements
    })
    .await
    .expect("bounded loopback comparison did not finish");
    println!(
        "FRAME_LATENCY {}",
        serde_json::to_string(&measurements).unwrap()
    );
}
