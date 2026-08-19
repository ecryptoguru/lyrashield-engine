// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! LyraShield Local — desktop shell library.
//!
//! Spawns the engine CLI as a subprocess, streams stdout/stderr to the
//! webview via Tauri events, and manages the local results store path.
//! Credentials live in the OS keychain (never plaintext). License is
//! ed25519-signed with offline grace + perpetual fallback + revocation list
//! check. Updates are signed and verified before applying. Cloud sync is
//! explicit opt-in only.

pub mod docker_detect;
pub mod keychain;
pub mod license;
pub mod scan;
pub mod sync;
pub mod updater;

use std::sync::Mutex;
use std::sync::OnceLock;

/// Global scan state shared across Tauri commands.
pub struct AppState {
    pub scan: Mutex<scan::ScanState>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            scan: Mutex::new(scan::ScanState::default()),
        }
    }
}

static STATE: OnceLock<AppState> = OnceLock::new();

pub fn state() -> &'static AppState {
    STATE.get_or_init(AppState::default)
}
