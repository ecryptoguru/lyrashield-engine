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

/// The signed license payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LicensePayload {
    /// Unique license id (used for revocation checks).
    pub license_id: String,
    /// Customer / seat name.
    pub name: String,
    /// Unix timestamp (seconds) the license was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) after which newer updates are refused.
    /// The app keeps running (perpetual fallback) but won't apply updates.
    pub update_eligible_until: u64,
    /// Last build number this license is eligible for.
    pub last_eligible_build: u64,
}

/// The license info returned to the webview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub license_id: String,
    pub name: String,
    pub issued_at: u64,
    pub update_eligible_until: u64,
    pub last_eligible_build: u64,
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

/// Activate a license from a base64 blob. Verifies the signature, checks the
/// revocation list, and caches the blob in the OS keychain.
pub fn activate(blob_b64: &str) -> Result<LicenseInfo, LicenseError> {
    let payload = verify_blob(blob_b64, BUNDLED_PUBKEY_HEX)?;
    let revocations = bundled_revocation_list();
    if is_revoked(&payload.license_id, &revocations) {
        return Err(LicenseError::Revoked);
    }
    // Cache the signed blob in the keychain (offline grace).
    keychain::set_license_cache(blob_b64).map_err(LicenseError::from)?;
    Ok(LicenseInfo {
        license_id: payload.license_id,
        name: payload.name,
        issued_at: payload.issued_at,
        update_eligible_until: payload.update_eligible_until,
        last_eligible_build: payload.last_eligible_build,
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
            let revocations = bundled_revocation_list();
            if is_revoked(&payload.license_id, &revocations) {
                return Ok(LicenseStatus {
                    active: false,
                    info: None,
                    message: "License revoked — contact support.".into(),
                });
            }
            Ok(LicenseStatus {
                active: true,
                info: Some(LicenseInfo {
                    license_id: payload.license_id,
                    name: payload.name,
                    issued_at: payload.issued_at,
                    update_eligible_until: payload.update_eligible_until,
                    last_eligible_build: payload.last_eligible_build,
                    revoked: false,
                }),
                message: "License active (offline grace).".into(),
            })
        }
    }
}

/// Perpetual fallback: given a cached license and a candidate build number,
/// return whether the update should be applied. Refuses newer builds after
/// `update_eligible_until` but never deactivates the running app.
pub fn should_accept_update(info: &LicenseInfo, now: u64, build: u64) -> bool {
    // After the eligibility window, refuse newer builds.
    if now > info.update_eligible_until {
        return build <= info.last_eligible_build;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{SigningKey, Signer};
    use rand::rngs::OsRng;

    fn mint_license(pubkey_hex: &str) -> (String, SigningKey) {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let payload = LicensePayload {
            license_id: "test-license-1".into(),
            name: "Test User".into(),
            issued_at: 1_000_000,
            update_eligible_until: 2_000_000,
            last_eligible_build: 100,
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = signing_key.sign(&payload_bytes);
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&payload_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        let _ = pubkey_hex; // pubkey_hex is used by the caller for verification
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
        assert_eq!(payload.license_id, "test-license-1");
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
        let payload = LicensePayload {
            license_id: "revoked-1".into(),
            name: "x".into(),
            issued_at: 1,
            update_eligible_until: 999_999_999,
            last_eligible_build: 1,
        };
        let revocations = vec![RevocationEntry {
            license_id: "revoked-1".into(),
            reason: "fraud".into(),
        }];
        assert!(is_revoked(&payload.license_id, &revocations));
    }

    #[test]
    fn test_perpetual_fallback_refuses_newer_after_window() {
        let info = LicenseInfo {
            license_id: "x".into(),
            name: "x".into(),
            issued_at: 1,
            update_eligible_until: 1000,
            last_eligible_build: 50,
            revoked: false,
        };
        // Before the window: accept any build.
        assert!(should_accept_update(&info, 500, 999));
        // After the window: refuse newer builds.
        assert!(!should_accept_update(&info, 2000, 60));
        // After the window: accept builds <= last eligible (perpetual fallback).
        assert!(should_accept_update(&info, 2000, 50));
        assert!(should_accept_update(&info, 2000, 40));
    }

    #[test]
    fn test_malformed_blob() {
        let result = verify_blob("not-a-blob", BUNDLED_PUBKEY_HEX);
        assert!(matches!(result, Err(LicenseError::Malformed)));
    }

    #[test]
    fn test_expired_update_window_still_runs() {
        // The perpetual fallback never deactivates — status() should still
        // return active for a cached license even after the update window.
        // (This is a logic check; the keychain is not exercised here.)
        let info = LicenseInfo {
            license_id: "x".into(),
            name: "x".into(),
            issued_at: 1,
            update_eligible_until: 1,
            last_eligible_build: 1,
            revoked: false,
        };
        // After window with an old build: still accepted.
        assert!(should_accept_update(&info, 9_999_999, 1));
    }
}
