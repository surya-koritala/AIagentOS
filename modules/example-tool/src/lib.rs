//! Example WASM tool module for AI Agent OS.
//!
//! Demonstrates a simple module that provides file search and word count tools.
//! In a real deployment, this would be compiled to wasm32-wasi and loaded by the kernel.

/// Count words in the given text.
#[no_mangle]
pub extern "C" fn word_count(ptr: *const u8, len: usize) -> usize {
    let text = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(ptr, len)) };
    text.split_whitespace().count()
}

/// Simple greeting to verify the module loads correctly.
#[no_mangle]
pub extern "C" fn hello() -> i32 {
    42
}
