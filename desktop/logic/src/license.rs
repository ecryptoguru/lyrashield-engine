// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! Pure license logic shared by the desktop shell and the standalone test
//! crate: signature verification, admission rules, revocation, perpetual
//! fallback. Keychain-coupled persistence and online calls live in the app
//! crate (`desktop/src-tauri/src/license.rs`).

use base64::Engine;
use keyring;
use ed25519_dalek::{Signature, VerifyingKey};
use std::cmp::Ordering;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const LICENSE_CACHE_KEY: &str = "license-cache";
pub const LAST_VALIDATED_KEY: &str = "license-last-validated";
pub const MACHINE_ID_KEY: &str = "machine-id";

/// Offline grace after a successful online activation, in seconds (30 days).
/// Scanning never phones home; only license revalidation does, after this window.
pub const OFFLINE_GRACE_SECS: u64 = 30 * 24 * 60 * 60;

/// Production activate endpoint. Overridable via `LYRASHIELD_API_URL`.
pub const DEFAULT_API_BASE: &str = "https://app.lyrashieldai.com";

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("license blob is malformed")]
    Malformed,
    #[error("license signature is invalid")]
    InvalidSignature,
    #[error("license is revoked — contact support")]
    Revoked,
    #[error("license payload is invalid: {0}")]
    InvalidPayload(String),
    #[error("keychain error: {0}")]
    Keychain(String),
    #[error("base64 decode error: {0}")]
    Base64(String),
    #[error("ed25519 error: {0}")]
    Ed25519(String),
    #[error("license request error: {0}")]
    Request(String),
    #[error("activation refused: {0}")]
    ActivationRefused(String),
}

impl From<keyring::Error> for LicenseError {
    fn from(e: keyring::Error) -> Self {
        LicenseError::Keychain(e.to_string())
    }
}

impl From<crate::keychain::KeychainError> for LicenseError {
    fn from(e: crate::keychain::KeychainError) -> Self {
        LicenseError::Keychain(e.to_string())
    }
}

impl From<base64::DecodeError> for LicenseError {
    fn from(e: base64::DecodeError) -> Self {
        LicenseError::Base64(e.to_string())
    }
}

impl From<ed25519_dalek::ed25519::Error> for LicenseError {
    fn from(e: ed25519_dalek::ed25519::Error) -> Self {
        LicenseError::Ed25519(e.to_string())
    }
}

/// The signed license payload — mirrors the TypeScript `LicensePayload` in
/// packages/licenses/src/types.ts. Field names use camelCase + serde rename
/// so the canonical JSON matches the server's `signLicense()` output exactly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LicensePayload {
    #[serde(rename = "sku")]
    pub sku: String,
    #[serde(rename = "seatCount")]
    pub seat_count: u32,
    #[serde(rename = "machineIds")]
    pub machine_ids: Vec<String>,
    #[serde(rename = "updateEligibleUntil")]
    pub update_eligible_until: String,
    #[serde(rename = "perpetualFallbackBuild")]
    pub perpetual_fallback_build: Option<String>,
}

/// The license info returned to the webview (camelCase: this struct is the
/// frontend/native JSON contract, shared with
/// desktop/ui/src/fixtures/license-contract.json).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LicenseInfo {
    pub sku: String,
    pub seat_count: u32,
    pub machine_ids: Vec<String>,
    pub update_eligible_until: String,
    pub perpetual_fallback_build: Option<String>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseStatus {
    pub active: bool,
    pub info: Option<LicenseInfo>,
    pub message: String,
}

/// A bundled revocation list entry. Shipped with signed updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub license_id: String,
    pub reason: String,
}

/// The bundled revocation list. In production this is embedded at build time.
pub fn bundled_revocation_list() -> Vec<RevocationEntry> {
    Vec::new()
}

/// Verify a license blob (`<base64(json)>.<base64(sig)>`) against a pubkey.
pub fn verify_blob(blob: &str, pubkey_hex: &str) -> Result<LicensePayload, LicenseError> {
    let (payload_b64, sig_b64) = blob.split_once('.').ok_or(LicenseError::Malformed)?;

    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .map_err(LicenseError::from)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(LicenseError::from)?;

    let pubkey_bytes = hex::decode(pubkey_hex).map_err(|e| LicenseError::Ed25519(e.to_string()))?;
    if pubkey_bytes.len() != 32 {
        return Err(LicenseError::InvalidPayload("pubkey must be 32 bytes".into()));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pubkey_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pk).map_err(LicenseError::from)?;

    if sig_bytes.len() != 64 {
        return Err(LicenseError::Malformed);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify_strict(&payload_bytes, &signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    let payload: LicensePayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| LicenseError::InvalidPayload(e.to_string()))?;

    Ok(payload)
}

/// Check whether a license id is in the revocation list.
pub fn is_revoked(license_id: &str, revocation_list: &[RevocationEntry]) -> bool {
    revocation_list.iter().any(|e| e.license_id == license_id)
}

/// Pure admission rule (C2), table-testable without a keychain: an inactive,
/// revoked, unvalidated, or grace-expired license denies the scan. A license
/// validated within the grace window scans even while offline.
pub fn admission_decision(
    active: bool,
    message: &str,
    last_validated: u64,
    now: u64,
) -> Result<(), String> {
    if !active {
        return Err(message.to_string());
    }
    if last_validated == 0 {
        return Err("license has never been validated online — activate first".into());
    }
    let age = now.saturating_sub(last_validated);
    if age > OFFLINE_GRACE_SECS {
        return Err("license offline grace expired — connect online and revalidate".into());
    }
    Ok(())
}

/// Perpetual fallback: given a cached license and a candidate build version,
/// return whether the update should be applied. Refuses newer builds after
/// `update_eligible_until` expires but never deactivates the running app.
pub fn should_accept_update(info: &LicenseInfo, now: u64, build_version: &str) -> bool {
    if info.revoked {
        return false;
    }
    let eligible = parse_iso_to_unix(&info.update_eligible_until).unwrap_or(0);
    if now > eligible {
        if let Some(fallback) = &info.perpetual_fallback_build {
            return compare_versions(build_version, fallback) != Ordering::Greater;
        }
        return false;
    }
    true
}

/// Numeric-segment semver comparison: returns Ordering (Less/Equal/Greater).
///
/// Pre-release tags like "1.2.0-beta" are stripped before comparison.
/// Non-numeric segments fall back to lexicographic comparison.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let clean_a = a.split('-').next().unwrap_or(a);
    let clean_b = b.split('-').next().unwrap_or(b);
    let pa: Vec<&str> = clean_a.split('.').collect();
    let pb: Vec<&str> = clean_b.split('.').collect();
    let len = pa.len().max(pb.len());
    for i in 0..len {
        let na = pa.get(i).copied().unwrap_or("0");
        let nb = pb.get(i).copied().unwrap_or("0");
        match (na.parse::<u64>(), nb.parse::<u64>()) {
            (Ok(va), Ok(vb)) => {
                if va < vb {
                    return Ordering::Less;
                }
                if va > vb {
                    return Ordering::Greater;
                }
            }
            _ => {
                if na < nb {
                    return Ordering::Less;
                }
                if na > nb {
                    return Ordering::Greater;
                }
            }
        }
    }
    Ordering::Equal
}

/// Parse an ISO 8601 timestamp to a Unix timestamp (seconds).
pub fn parse_iso_to_unix(iso: &str) -> Option<u64> {
    let ts = iso.strip_suffix('Z').unwrap_or(iso);
    let parts: Vec<&str> = ts.split('T').collect();
    if parts.len() != 2 {
        return None;
    }
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if date_parts.len() != 3 || time_parts.len() < 2 {
        return None;
    }
    let year: u64 = date_parts[0].parse().ok()?;
    let month: u64 = date_parts[1].parse().ok()?;
    let day: u64 = date_parts[2].parse().ok()?;
    let hour: u64 = time_parts[0].parse().ok()?;
    let min: u64 = time_parts[1].parse().ok()?;
    let sec: u64 = if time_parts.len() > 2 {
        time_parts[2].split('.').next()?.parse().ok()?
    } else {
        0
    };
    let days_since_epoch = days_from_civil(year as i32, month as i32, day as i32);
    Some((days_since_epoch as u64) * 86400 + hour * 3600 + min * 60 + sec)
}

/// Convert civil date to days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i32, m: i32, d: i32) -> i32 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
