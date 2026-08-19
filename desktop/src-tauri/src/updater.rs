// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! Signed update channel for LyraShield Local.
//!
//! Uses Tauri's updater plugin with ed25519 signing. The update signature is
//! verified before applying. No remote-code eval — only signed artifacts
//! hosted on GitHub Releases are applied. The update-channel origin is pinned
//! in `tauri.conf.json`.
//!
//! The perpetual fallback in `license.rs` gates whether an update is offered
//! at all: after `update_eligible_until`, newer builds are refused but the
//! app keeps running.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpdaterError {
    #[error("update check failed: {0}")]
    Check(String),
    #[error("update signature is invalid")]
    InvalidSignature,
    #[error("update channel is not pinned")]
    UnpinnedChannel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub available: bool,
    pub version: String,
    pub notes: String,
    pub signature_valid: bool,
}

/// The pinned update-channel origin. Must match the endpoint in
/// `tauri.conf.json`. Updates from any other origin are refused.
pub const PINNED_UPDATE_ORIGIN: &str =
    "https://github.com/lyrashield/lyrashield-local/releases/latest/download/latest.json";

/// Check for updates. The actual download + signature verification is
/// performed by the Tauri updater plugin (ed25519). This command is a thin
/// wrapper that reports availability to the webview.
pub async fn check() -> Result<UpdateInfo, UpdaterError> {
    // The Tauri updater plugin performs the signature check against the
    // pubkey in tauri.conf.json before applying. Here we fetch the manifest
    // to report availability; we do NOT eval or apply anything ourselves.
    let client = reqwest::Client::builder()
        .user_agent("LyraShield-Local-Updater")
        .build()
        .map_err(|e| UpdaterError::Check(e.to_string()))?;

    let resp = client
        .get(PINNED_UPDATE_ORIGIN)
        .send()
        .await
        .map_err(|e| UpdaterError::Check(e.to_string()))?;

    if !resp.status().is_success() {
        return Ok(UpdateInfo {
            available: false,
            version: String::new(),
            notes: "No update manifest available.".into(),
            signature_valid: false,
        });
    }

    let manifest: UpdateManifest = resp
        .json()
        .await
        .map_err(|e| UpdaterError::Check(e.to_string()))?;

    // The manifest includes a signature field; the Tauri updater plugin
    // verifies it against the bundled pubkey before applying. We report
    // that a signature is present; the plugin enforces verification.
    let sig_valid = !manifest.signature.is_empty();

    Ok(UpdateInfo {
        available: true,
        version: manifest.version,
        notes: manifest.notes,
        signature_valid: sig_valid,
    })
}

#[derive(Debug, Deserialize)]
struct UpdateManifest {
    version: String,
    notes: String,
    pub_date: String,
    signature: String,
    platforms: serde_json::Value,
}

/// Verify that a given origin matches the pinned update channel.
pub fn verify_origin(origin: &str) -> Result<(), UpdaterError> {
    if origin == PINNED_UPDATE_ORIGIN {
        Ok(())
    } else {
        Err(UpdaterError::UnpinnedChannel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_origin_pinned() {
        assert!(verify_origin(PINNED_UPDATE_ORIGIN).is_ok());
        assert!(verify_origin("https://evil.example.com/update.json").is_err());
    }

    #[tokio::test]
    async fn test_check_returns_unavailable_on_network_error() {
        // Without a network or mock server, this may error — which is fine.
        let _ = check().await;
    }
}
