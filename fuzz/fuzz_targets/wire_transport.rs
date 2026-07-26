#![no_main]

use kernel::exercise_fragmented_transport;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    exercise_fragmented_transport(data);
});
