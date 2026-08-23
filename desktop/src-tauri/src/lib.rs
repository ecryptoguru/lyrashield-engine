// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! LyraShield Local — desktop shell library.
//!
//! Spawns the bundled engine sidecar as a supervised subprocess, streams
//! stdout/stderr to the webview via Tauri events, and gates every scan on one
//! native license admission. Credentials live in the OS keychain (never
//! plaintext). License is ed25519-signed with offline grace + perpetual
//! fallback + revocation check. Updates are verified only by the Tauri
//! updater plugin. Cloud sync is explicit opt-in only.
//!
//! This library target is the single home of the desktop logic; the binary
//! (`main.rs`) only registers Tauri commands, and the standalone test crate
//! (`desktop/tests`) exercises this crate directly instead of re-implementing
//! it.

pub mod docker_detect;
pub mod keychain;
pub mod license;
pub mod scan;
pub mod sync;
pub mod updater;

use std::sync::OnceLock;

/// Global scan supervisor shared across Tauri commands.
pub struct AppState {
    pub scan: scan::ScanSupervisor,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            scan: scan::ScanSupervisor::default(),
        }
    }
}

static STATE: OnceLock<AppState> = OnceLock::new();

pub fn state() -> &'static AppState {
    STATE.get_or_init(AppState::default)
}
