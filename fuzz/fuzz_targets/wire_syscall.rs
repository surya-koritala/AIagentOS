#![no_main]

use kernel::syscall_server::Syscall;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The newline-delimited wire server deserializes untrusted JSON directly
    // into Syscall. Parsing arbitrary bytes must never panic or abort.
    let _ = serde_json::from_slice::<Syscall>(data);
});
