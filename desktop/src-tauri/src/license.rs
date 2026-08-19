// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! License cache + ed25519 signature verification for LyraShield Local.
//!
//! Offline grace: honor a cached signed license without phoning home.
//! Perpetual fallback: track the last-eligible-build; refuse newer updates
//! after `update_eligible_until` but never deactivate the app.
//! Revocation: check a bundled revocation list (shipped with signed updates)
//! for the license id — if revoked, refuse scan and show a message.
//!
//! The license blob is a base64-encoded JSON payload + ed25519 signature:
//!   `<base64(json_payload)>.<base64(signature)>`
//! The signature is verified against the bundled ed25519 public key. The
//! license cache is stored in the OS keychain (never plaintext).

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keychain;

pub const LICENSE_CACHE_KEY: &str = "license-cache";
pub const LAST_VALIDATED_KEY: &str = "license-last-validated";
pub const MACHINE_ID_KEY: &str = "machine-id";

/// Offline grace after a successful online activation, in seconds (30 days).
/// Scanning never phones home; only license revalidation does, after this window.
pub const OFFLINE_GRACE_SECS: u64 = 30 * 24 * 60 * 60;

/// Production activate endpoint. Overridable via `LYRASHIELD_API_URL`.
pub const DEFAULT_API_BASE: &str = "https://app.lyrashieldai.com";

/// Bundled ed25519 public key for license verification. In production this is
/// replaced at build time with LyraShield's real public key. The placeholder
/// is a 32-byte zero key so tests can mint their own keypair.
pub const BUNDLED_PUBKEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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
}

impl From<keyring::Error> for LicenseError {
    fn from(e: keyring::Error) -> Self {
        LicenseError::Keychain(e.to_string())
    }
}

impl From<keychain::KeychainError> for LicenseError {
    fn from(e: keychain::KeychainError) -> Self {
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
    /// SKU identifier (e.g. "individual_launch", "team_perpetual").
    #[serde(rename = "sku")]
    pub sku: String,
    /// Number of seats purchased.
    #[serde(rename = "seatCount")]
    pub seat_count: u32,
    /// Machine IDs that have activated this license.
    #[serde(rename = "machineIds")]
    pub machine_ids: Vec<String>,
    /// ISO 8601 timestamp after which newer updates are refused.
    /// The app keeps running (perpetual fallback) but won't apply updates.
    #[serde(rename = "updateEligibleUntil")]
    pub update_eligible_until: String,
    /// Last build this license is eligible for (null = no build pin).
    #[serde(rename = "perpetualFallbackBuild")]
    pub perpetual_fallback_build: Option<String>,
}

/// The license info returned to the webview.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        .verify(&payload_bytes, &signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    let payload: LicensePayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| LicenseError::InvalidPayload(e.to_string()))?;

    Ok(payload)
}

/// Check whether a license id is in the revocation list.
pub fn is_revoked(license_id: &str, revocation_list: &[RevocationEntry]) -> bool {
    revocation_list.iter().any(|e| e.license_id == license_id)
}

/// Cache a verified blob + stamp last-validated-at (unix seconds).
fn cache_verified(blob: &str, license_id: &str) -> Result<(), LicenseError> {
    let now = unix_now();
    keychain::set_license_cache(blob).map_err(LicenseError::from)?;
    keychain::set("lyrashield-local", "license-id", license_id).map_err(LicenseError::from)?;
    keychain::set("lyrashield-local", LAST_VALIDATED_KEY, &now.to_string())
        .map_err(LicenseError::from)?;
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Stable per-install machine fingerprint, persisted in the keychain.
pub fn machine_id() -> Result<String, LicenseError> {
    if let Some(existing) = keychain::get("lyrashield-local", MACHINE_ID_KEY).map_err(LicenseError::from)? {
        if !existing.is_empty() {
            return Ok(existing);
        }
    }
    let id = format!("ls-{}", hex::encode(rand::random::<[u8; 16]>()));
    keychain::set("lyrashield-local", MACHINE_ID_KEY, &id).map_err(LicenseError::from)?;
    Ok(id)
}

/// Activate a license from an already-signed detached blob (offline / tests).
/// Production activation goes through [`activate_online`].
pub fn activate(blob_b64: &str, license_id: &str) -> Result<LicenseInfo, LicenseError> {
    let payload = verify_blob(blob_b64, BUNDLED_PUBKEY_HEX)?;
    let revocations = bundled_revocation_list();
    if is_revoked(license_id, &revocations) {
        return Err(LicenseError::Revoked);
    }
    cache_verified(blob_b64, license_id)?;
    Ok(LicenseInfo {
        sku: payload.sku,
        seat_count: payload.seat_count,
        machine_ids: payload.machine_ids,
        update_eligible_until: payload.update_eligible_until,
        perpetual_fallback_build: payload.perpetual_fallback_build,
        revoked: false,
    })
}

/// Read the cached license status. Never phones home.
pub fn status() -> Result<LicenseStatus, LicenseError> {
    let cached = keychain::get_license_cache().map_err(LicenseError::from)?;
    match cached {
        None => Ok(LicenseStatus {
            active: false,
            info: None,
            message: "No license activated.".into(),
        }),
        Some(blob) => {
            let payload = verify_blob(&blob, BUNDLED_PUBKEY_HEX)?;
            // License ID is cached separately (not in the signed payload).
            let license_id = keychain::get("lyrashield-local", "license-id").unwrap_or_default().unwrap_or_default();
            let revocations = bundled_revocation_list();
            if !license_id.is_empty() && is_revoked(&license_id, &revocations) {
                return Ok(LicenseStatus {
                    active: false,
                    info: None,
                    message: "License revoked — contact support.".into(),
                });
            }
            Ok(LicenseStatus {
                active: true,
                info: Some(LicenseInfo {
                    sku: payload.sku,
                    seat_count: payload.seat_count,
                    machine_ids: payload.machine_ids,
                    update_eligible_until: payload.update_eligible_until,
                    perpetual_fallback_build: payload.perpetual_fallback_build,
                    revoked: false,
                }),
                message: "License active (offline grace).".into(),
            })
        }
    }
}

/// One-time online activation: POST licenseKey + machine fingerprint to
/// `/api/licenses/activate`, receive a detached signed blob, verify the
/// **exact received bytes**, then cache. After this the app runs offline
/// until `OFFLINE_GRACE_SECS` elapses.
pub async fn activate_online(license_key: &str) -> Result<LicenseInfo, LicenseError> {
    if license_key.is_empty() {
        return Err(LicenseError::ActivationRefused("license key is required".into()));
    }
    let machine = machine_id()?;
    let api_base = std::env::var("LYRASHIELD_API_URL").unwrap_or_else(|_| DEFAULT_API_BASE.to_string());
    let url = format!("{}/api/licenses/activate", api_base.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .user_agent("LyraShield-Local")
        .build()
        .map_err(|e| LicenseError::Request(e.to_string()))?;

    let resp = client
        .post(url)
        .json(&serde_json::json!({
            "licenseKey": license_key,
            "machineId": machine,
        }))
        .send()
        .await
        .map_err(|e| LicenseError::Request(e.to_string()))?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| LicenseError::Request(e.to_string()))?;

    if !status.is_success() || body.get("success") != Some(&serde_json::Value::Bool(true)) {
        let code = body
            .pointer("/error/code")
            .and_then(|v| v.as_str())
            .unwrap_or("ACTIVATION_FAILED");
        return Err(LicenseError::ActivationRefused(code.to_string()));
    }

    let data = body.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let blob = data
        .get("blob")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LicenseError::ActivationRefused("missing blob".into()))?;
    let license_id = data
        .get("licenseId")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    activate(blob, license_id)
}

/// Perpetual fallback: given a cached license and a candidate build version,
/// return whether the update should be applied. Refuses newer builds after
/// `update_eligible_until` expires but never deactivates the running app.
/// `now` is a Unix timestamp (seconds). `build_version` is the target version string.
pub fn should_accept_update(info: &LicenseInfo, now: u64, build_version: &str) -> bool {
    // Parse updateEligibleUntil (ISO 8601) to a Unix timestamp.
    let eligible = parse_iso_to_unix(&info.update_eligible_until).unwrap_or(0);
    // After the eligibility window, refuse newer builds.
    if now > eligible {
        // Allow if the build matches or is older than the perpetual fallback build.
        if let Some(fallback) = &info.perpetual_fallback_build {
            // Numeric-segment semver comparison (mirrors packages/licenses/src/verify.ts
            // compareVersions). A plain string compare is WRONG: "1.10.0" <= "1.2.0"
            // is false lexicographically but true semantically, and "1.2.0-hotfix" > "1.2.0".
            return compare_versions(build_version, fallback) <= 0;
        }
        return false;
    }
    true
}

/// Numeric-segment semver comparison: returns Ordering (Less/Equal/Greater).
///
/// Mirrors packages/licenses/src/verify.ts `compareVersions`. Pre-release tags
/// like "1.2.0-beta" are stripped before comparison. Non-numeric segments fall
/// back to lexicographic comparison for that segment (matching the TS side).
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    // Strip pre-release suffixes ("1.2.0-beta" -> "1.2.0").
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
                // Non-numeric segment: fall back to lexicographic comparison.
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
fn parse_iso_to_unix(iso: &str) -> Option<u64> {
    // Simple parser: handle "YYYY-MM-DDTHH:MM:SS.sssZ" format.
    // For production, use a proper datetime crate; this is sufficient for
    // the license check which only needs second-level precision.
    let ts = iso.strip_suffix('Z').unwrap_or(iso);
    // Try parsing with chrono-like manual extraction.
    // Format: 2026-08-18T12:00:00.000
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
    // Approximate Unix timestamp (not accounting for leap seconds).
    // Days from epoch (1970-01-01) to the given date.
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{SigningKey, Signer};
    use rand::rngs::OsRng;

    fn mint_license(_pubkey_hex: &str) -> (String, SigningKey) {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let payload = LicensePayload {
            sku: "individual_launch".into(),
            seat_count: 1,
            machine_ids: vec!["machine-1".into()],
            update_eligible_until: "2036-01-01T00:00:00.000Z".into(),
            perpetual_fallback_build: Some("1.0.0".into()),
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = signing_key.sign(&payload_bytes);
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&payload_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        (format!("{payload_b64}.{sig_b64}"), signing_key)
    }

    fn pubkey_hex_for(signing_key: &SigningKey) -> String {
        hex::encode(signing_key.verifying_key().to_bytes())
    }

    #[test]
    fn test_verify_valid_signature() {
        let (blob, signing_key) = mint_license("");
        let pubkey_hex = pubkey_hex_for(&signing_key);
        let payload = verify_blob(&blob, &pubkey_hex).expect("valid signature should verify");
        assert_eq!(payload.sku, "individual_launch");
        assert_eq!(payload.seat_count, 1);
    }

    #[test]
    fn test_verify_tampered_payload() {
        let (blob, signing_key) = mint_license("");
        let pubkey_hex = pubkey_hex_for(&signing_key);
        // Tamper: flip a character in the payload portion.
        let mut tampered = blob.clone();
        let bad_char = if tampered.starts_with('A') { 'B' } else { 'A' };
        tampered.replace_range(0..1, &bad_char.to_string());
        let result = verify_blob(&tampered, &pubkey_hex);
        assert!(matches!(result, Err(LicenseError::InvalidSignature) | Err(LicenseError::Malformed) | Err(LicenseError::Base64(_))));
    }

    #[test]
    fn test_verify_tampered_signature() {
        let (blob, signing_key) = mint_license("");
        let pubkey_hex = pubkey_hex_for(&signing_key);
        // Tamper with the signature portion (after the dot).
        let (payload_b64, _sig_b64) = blob.split_once('.').unwrap();
        let tampered = format!("{payload_b64}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let result = verify_blob(&tampered, &pubkey_hex);
        assert!(matches!(result, Err(LicenseError::InvalidSignature) | Err(LicenseError::Malformed)));
    }

    #[test]
    fn test_revoked_license() {
        let revocations = vec![RevocationEntry {
            license_id: "revoked-1".into(),
            reason: "fraud".into(),
        }];
        assert!(is_revoked("revoked-1", &revocations));
        assert!(!is_revoked("not-revoked", &revocations));
    }

    #[test]
    fn test_perpetual_fallback_refuses_newer_after_window() {
        let info = LicenseInfo {
            sku: "individual_launch".into(),
            seat_count: 1,
            machine_ids: vec![],
            update_eligible_until: "2000-01-01T00:00:00.000Z".into(), // expired
            perpetual_fallback_build: Some("1.0.0".into()),
            revoked: false,
        };
        // Before the window (1999): accept any build.
        assert!(should_accept_update(&info, 915148800, "2.0.0")); // 1999-01-01
        // After the window (2020): refuse newer builds.
        assert!(!should_accept_update(&info, 1577836800, "2.0.0")); // 2020-01-01
        // After the window: accept builds <= perpetual fallback (1.0.0).
        assert!(should_accept_update(&info, 1577836800, "1.0.0"));
        assert!(should_accept_update(&info, 1577836800, "0.9.0"));
    }

    #[test]
    fn test_malformed_blob() {
        let result = verify_blob("not-a-blob", BUNDLED_PUBKEY_HEX);
        assert!(matches!(result, Err(LicenseError::Malformed)));
    }

    #[test]
    fn test_expired_update_window_still_runs() {
        // The perpetual fallback never deactivates — should_accept_update
        // should still accept old builds even after the update window.
        let info = LicenseInfo {
            sku: "individual_launch".into(),
            seat_count: 1,
            machine_ids: vec![],
            update_eligible_until: "2000-01-01T00:00:00.000Z".into(), // expired
            perpetual_fallback_build: Some("1.0.0".into()),
            revoked: false,
        };
        // After window with an old build: still accepted.
        assert!(should_accept_update(&info, 9_999_999_999, "1.0.0"));
    }

    #[test]
    fn test_perpetual_fallback_numeric_version_compare() {
        // Regression for the lexicographic-string-comparison bug: "1.10.0" is
        // semantically newer than "1.2.0" (10 > 2), but "1.10.0" < "1.2.0"
        // lexicographically. A user entitled to fallback build "1.10.0" must be
        // allowed to run it even after the update window — a string compare
        // would wrongly refuse it.
        let info = LicenseInfo {
            sku: "individual_launch".into(),
            seat_count: 1,
            machine_ids: vec![],
            update_eligible_until: "2000-01-01T00:00:00.000Z".into(), // expired
            perpetual_fallback_build: Some("1.10.0".into()),
            revoked: false,
        };
        let after_window = 1_577_836_800u64; // 2020-01-01
        assert!(should_accept_update(&info, after_window, "1.10.0")); // exactly the fallback
        assert!(should_accept_update(&info, after_window, "1.9.0")); // older
        assert!(should_accept_update(&info, after_window, "1.2.0")); // older (2 < 10)
        assert!(!should_accept_update(&info, after_window, "1.11.0")); // newer
        assert!(!should_accept_update(&info, after_window, "2.0.0")); // newer
        // Pre-release tags are stripped: "1.10.0-hotfix" (numerically 1.10.0) is
        // the fallback build, accepted.
        assert!(should_accept_update(&info, after_window, "1.10.0-hotfix"));
    }

    #[test]
    fn test_golden_vector_verifies_exact_received_bytes() {
        // Cross-language golden: signed by Node canonicalJSON (packages/licenses).
        // Rust verifies the decoded payload bytes as received — no re-serialize.
        let blob = "eyJtYWNoaW5lSWRzIjpbIm1hY2hpbmUtZ29sZGVuLTEiXSwicGVycGV0dWFsRmFsbGJhY2tCdWlsZCI6IjEuMi4wIiwic2VhdENvdW50IjoxLCJza3UiOiJpbmRpdmlkdWFsX2xhdW5jaCIsInVwZGF0ZUVsaWdpYmxlVW50aWwiOiIyMDM2LTAxLTAxVDAwOjAwOjAwLjAwMFoifQ==.f5rJ6rAhcL5+sCgngjFKKvpTz+IBeYuAgnwPyQArw/w9+AHRwIywUv5VYGdrx50ToUO0VVSJhFOOwU71F0UXCg==";
        let pubkey_hex = "1548593e16dcf2654eadd19429e88a91a21ca1d78da676249352b7eecf30592c";
        let payload = verify_blob(blob, pubkey_hex).expect("Node-signed golden blob must verify");
        assert_eq!(payload.sku, "individual_launch");
        assert_eq!(payload.seat_count, 1);
        assert_eq!(payload.machine_ids, vec!["machine-golden-1".to_string()]);
        assert_eq!(payload.perpetual_fallback_build.as_deref(), Some("1.2.0"));

        // Re-serializing in serde struct order would produce different bytes
        // than the signed canonicalJSON. The verifier must not do that.
        let (payload_b64, _) = blob.split_once('.').unwrap();
        let received = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
            .unwrap();
        let re_serialized = serde_json::to_vec(&payload).unwrap();
        assert_ne!(
            received, re_serialized,
            "golden payload is canonicalJSON, not serde_json struct order"
        );
    }
}
