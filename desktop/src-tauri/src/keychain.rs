// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! OS keychain integration for LyraShield Local.
//!
//! The implementation lives in the shared `lyrashield-desktop-logic` crate so
//! the Tauri shell and the standalone test crate exercise one code path.

pub use lyrashield_desktop_logic::keychain::*;
