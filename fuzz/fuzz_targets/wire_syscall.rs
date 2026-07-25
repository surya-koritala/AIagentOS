#![no_main]

use kernel::mcp_server::JsonRpcRequest;
use kernel::syscall_server::{Syscall, SyscallReply};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Syscall and MCP servers plus non-Rust/SDK clients deserialize untrusted
    // JSON into these public envelopes. Requests, replies, malformed partial
    // frames, and cross-protocol/out-of-order payloads must never panic.
    let _ = serde_json::from_slice::<Syscall>(data);
    let _ = serde_json::from_slice::<SyscallReply>(data);
    let _ = serde_json::from_slice::<JsonRpcRequest>(data);
});
