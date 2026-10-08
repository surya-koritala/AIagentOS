# UTF-8 byte-budget coding task

This dependency-free Rust project deliberately contains a failing implementation
of `bounded_prefix`. Its tests specify a maximal borrowed UTF-8 prefix whose
length does not exceed a byte budget. The ASCII cases pass; cutting through a
multibyte code point panics.

The coding task is: fix `src/lib.rs` while preserving the public signature and
tests. A candidate that treats the byte budget as a character count is incorrect,
even when it avoids the panic. The deterministic branch workflow must reject
that candidate and select the implementation that respects both UTF-8 boundaries
and the byte limit.

Only `src/lib.rs` may be edited. The separate test file is immutable input, and
its digest must be checked before and after each candidate test run. Invoke the
named integration target so deleting or disabling the tests cannot look successful.

Run the actual tests inside the supported digest-pinned Rust/rootless-container
backend with `cargo test --test utf8_budget --offline --locked`. No dependency installation, network,
credential access or original-worktree write is required. This directory is
outside the primary Cargo workspace because its baseline failure is intentional.

This is a scripted task fixture for #394. It does not establish real-provider
quality, package installation or production qualification.
