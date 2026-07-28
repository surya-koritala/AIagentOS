//! Built-in resource providers for the AI Agent OS.
//!
//! Lean by default: network and one-shot application launch remain experimental
//! standalone helpers. Filesystem and peripheral compatibility types advertise
//! no operations because they lack kernel-owned sandbox or operator-grant
//! authority. The HTML-scraping `browser` and headless-browser `playwright`
//! providers are gated behind cargo features so a vanilla build doesn't pull
//! ~50 MB of optional code.

pub mod application;
pub mod filesystem;
pub mod network;
pub mod peripheral;

#[cfg(feature = "web")]
pub mod browser;

#[cfg(feature = "browser")]
pub mod playwright;
