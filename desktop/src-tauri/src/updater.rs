// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! Signed update channel for LyraShield Local (D3).
//!
//! Authority rules:
//! - Only the Tauri updater plugin (ed25519, pubkey pinned in
//!   `tauri.conf.json`) verifies manifests and artifacts. Nothing in this
//!   app treats a non-empty signature string as "verified" — the webview only
//!   learns an update is verified after the plugin has accepted it.
//! - License/update eligibility is checked natively immediately before an
//!   offer, download, or install — not only when the update screen opens.
//! - The webview holds no updater or process permissions; it can only call
//!   the narrow native commands in `main.rs`.

use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpdaterError {
    #[error("update check failed: {0}")]
    Check(String),
    #[error("update channel is not pinned")]
    UnpinnedChannel,
    #[error("not licensed for updates: {0}")]
    NotEligible(String),
    #[error("no verified update available")]
    NoVerifiedUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub available: bool,
    pub version: String,
    pub notes: String,
}

/// The pinned update-channel origin. Must match the endpoint in
/// `tauri.conf.json`. Updates from any other origin are refused.
pub const PINNED_UPDATE_ORIGIN: &str =
    "https://github.com/lyrashield/lyrashield-local/releases/latest/download/latest.json";

/// Native eligibility immediately before an offer/download/install (I16):
/// revoked, inactive, stale, or build-ineligible licenses fail closed. A
/// license that needs online revalidation must revalidate before an update
/// is offered or installed, otherwise a recently revoked license can still
/// update using stale local state.
async fn update_eligibility(now: u64, candidate_version: &str) -> Result<(), UpdaterError> {
    let mut status = crate::license::status().map_err(|e| UpdaterError::NotEligible(e.to_string()))?;
    if status.active && status.needs_revalidation {
        status = crate::license::revalidate_online()
            .await
            .map_err(|e| UpdaterError::NotEligible(e.to_string()))?;
    }
    if !status.active {
        return Err(UpdaterError::NotEligible(status.message));
    }
    let info = match status.info {
        Some(info) => info,
        None => return Err(UpdaterError::NotEligible("license state incomplete".into())),
    };
    let current_version = env!("CARGO_PKG_VERSION");
    let accept_current = crate::license::should_accept_update(&info, now, current_version);
    let accept_candidate = crate::license::should_accept_update(&info, now, candidate_version);
    if !accept_current || !accept_candidate {
        return Err(UpdaterError::NotEligible(
            "license update window expired — the app keeps running (perpetual fallback) \
             but newer builds are not offered"
                .into(),
        ));
    }
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Check for a verified update (C5): availability is reported by the Tauri
/// updater plugin itself, after its signature checks. Eligibility is
/// re-checked here, immediately before the offer.
pub async fn check_with_eligibility(app: &AppHandle) -> Result<UpdateInfo, UpdaterError> {
    let updater = app
        .updater_builder()
        .build()
        .map_err(|e| UpdaterError::Check(e.to_string()))?;
    let update = updater
        .check()
        .await
        .map_err(|e| UpdaterError::Check(e.to_string()))?;
    match update {
        None => Ok(UpdateInfo {
            available: false,
            version: String::new(),
            notes: "You are on the latest version.".into(),
        }),
        Some(update) => {
            update_eligibility(unix_now(), &update.version).await?;
            Ok(UpdateInfo {
                available: true,
                version: update.version.clone(),
                notes: update.body.clone().unwrap_or_default(),
            })
        }
    }
}

/// Download and install an update through the Tauri updater plugin. The
/// plugin verifies the manifest signature and the artifact signature against
/// the pinned pubkey; a tampered manifest, tampered artifact, forged
/// signature, or wrong origin fails here. Eligibility is re-checked
/// immediately before the download begins.
pub async fn install_with_verification(
    app: &AppHandle,
    accepted_version: &str,
) -> Result<(), UpdaterError> {
    let updater = app
        .updater_builder()
        .build()
        .map_err(|e| UpdaterError::Check(e.to_string()))?;
    let update = updater
        .check()
        .await
        .map_err(|e| UpdaterError::Check(e.to_string()))?
        .ok_or(UpdaterError::NoVerifiedUpdate)?;
    if update.version != accepted_version {
        return Err(UpdaterError::Check(format!(
            "accepted version {accepted_version} does not match the update server version {}",
            update.version
        )));
    }
    update_eligibility(unix_now(), &update.version).await?;
    // download() verifies the artifact signature against the pinned pubkey
    // before returning bytes; install() applies exactly those bytes.
    let downloaded = update
        .download(|_chunk, _total| {}, || {})
        .await
        .map_err(|e| UpdaterError::Check(format!("verified download failed: {e}")))?;
    update
        .install(downloaded)
        .map_err(|e| UpdaterError::Check(format!("verified install failed: {e}")))?;
    Ok(())
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
}
