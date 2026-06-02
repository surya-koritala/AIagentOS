//! `agent-tui` — Rust terminal UI for AI Agent OS.
//!
//! The library exposes the render-free [`app`] state machine (so it can be
//! unit/integration tested); the `agent-tui` binary (`src/main.rs`) wires it to
//! a terminal and the kernel syscall server.

pub mod app;
