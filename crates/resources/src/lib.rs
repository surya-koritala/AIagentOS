//! Built-in resource providers for the AI Agent OS.
//!
//! Lean by default: filesystem, network, application, peripheral. The
//! HTML-scraping `browser` and headless-browser `playwright` providers are
//! gated behind cargo features so a vanilla build doesn't pull ~50 MB of
//! optional code.

pub mod application;
pub mod filesystem;
pub mod network;
pub mod peripheral;

#[cfg(feature = "web")]
pub mod browser;

#[cfg(feature = "browser")]
pub mod playwright;
