// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! Optional cloud-sync client for LyraShield Local.
//!
//! Explicit opt-in only: nothing syncs by default. The user must connect to
//! their LyraShield account (OAuth device flow or `LYRASHIELD_API_KEY`).
//! Sync sends chosen findings/reports over TLS. The sync entitlement is
//! enforced server-side — the client cannot bypass it.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::sync::OnceLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("sync is not enabled — opt in first")]
    NotEnabled,
    #[error("api key is required to connect")]
    MissingApiKey,
    #[error("sync request failed: {0}")]
    Request(String),
    #[error("sync entitlement denied by server")]
    EntitlementDenied,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncState {
    pub connected: bool,
    pub api_key_set: bool,
    pub last_synced_at: Option<u64>,
    pub entitlement_ok: bool,
}

static SYNC_STATE: OnceLock<Mutex<SyncState>> = OnceLock::new();

fn sync_state() -> &'static Mutex<SyncState> {
    SYNC_STATE.get_or_init(|| Mutex::new(SyncState::default()))
}

/// The LyraShield sync API base. Enforced server-side for entitlement.
pub const SYNC_API_BASE: &str = "https://api.lyrashield.dev";

/// Connect to the LyraShield sync service with an API key. Explicit opt-in.
pub async fn connect(api_key: &str) -> Result<SyncState, SyncError> {
    if api_key.is_empty() {
        return Err(SyncError::MissingApiKey);
    }

    // Issue a tiny entitlement check. The server enforces the sync entitlement.
    let client = reqwest::Client::builder()
        .user_agent("LyraShield-Local-Sync")
        .build()
        .map_err(|e| SyncError::Request(e.to_string()))?;

    let resp = client
        .get(format!("{SYNC_API_BASE}/v1/sync/entitlement"))
        .bearer_auth(api_key)
        .send()
        .await
        .map_err(|e| SyncError::Request(e.to_string()))?;

    let entitlement_ok = resp.status().is_success();
    if !entitlement_ok && resp.status().as_u16() == 403 {
        return Err(SyncError::EntitlementDenied);
    }

    let mut state = sync_state().lock().unwrap();
    state.connected = entitlement_ok;
    state.api_key_set = true;
    state.entitlement_ok = entitlement_ok;
    Ok(state.clone())
}

/// Return the current sync state. Nothing syncs unless `connected` is true.
pub async fn status() -> Result<SyncState, SyncError> {
    let state = sync_state().lock().unwrap().clone();
    Ok(state)
}

/// Sync a chosen finding/report payload. Only if connected + entitled.
pub async fn sync_payload(api_key: &str, payload: &serde_json::Value) -> Result<(), SyncError> {
    let state = sync_state().lock().unwrap().clone();
    if !state.connected || !state.entitlement_ok {
        return Err(SyncError::NotEnabled);
    }

    let client = reqwest::Client::builder()
        .user_agent("LyraShield-Local-Sync")
        .build()
        .map_err(|e| SyncError::Request(e.to_string()))?;

    let resp = client
        .post(format!("{SYNC_API_BASE}/v1/sync/findings"))
        .bearer_auth(api_key)
        .json(payload)
        .send()
        .await
        .map_err(|e| SyncError::Request(e.to_string()))?;

    if resp.status().as_u16() == 403 {
        return Err(SyncError::EntitlementDenied);
    }
    if !resp.status().is_success() {
        return Err(SyncError::Request(format!("HTTP {}", resp.status())));
    }
    Ok(())
}

/// Disconnect and disable sync.
pub fn disconnect() {
    let mut state = sync_state().lock().unwrap();
    state.connected = false;
    state.entitlement_ok = false;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_state_defaults_to_disconnected() {
        // Fresh state is disconnected — nothing syncs by default.
        let state = SyncState::default();
        assert!(!state.connected);
        assert!(!state.api_key_set);
        assert!(!state.entitlement_ok);
    }

    #[tokio::test]
    async fn test_connect_rejects_empty_api_key() {
        let result = connect("").await;
        assert!(matches!(result, Err(SyncError::MissingApiKey)));
    }

    #[tokio::test]
    async fn test_sync_payload_requires_connection() {
        // Without a connection, sync_payload refuses.
        let payload = serde_json::json!({"finding": "x"});
        let result = sync_payload("key", &payload).await;
        assert!(matches!(result, Err(SyncError::NotEnabled)));
    }
}
