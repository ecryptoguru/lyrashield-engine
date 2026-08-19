// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! Standalone desktop logic tests — runnable without a Tauri context.
//!
//! These mirror the `#[cfg(test)]` modules inside src-tauri/src but are
//! collected here so `cargo test` works without `tauri::generate_context!`
//! (which requires the built frontend dist).

mod license_logic;
mod sync_logic;
mod updater_logic;
mod docker_logic;
mod keychain_logic;

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct LicensePayload {
    license_id: String,
    name: String,
    issued_at: u64,
    update_eligible_until: u64,
    last_eligible_build: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LicenseInfo {
    license_id: String,
    name: String,
    issued_at: u64,
    update_eligible_until: u64,
    last_eligible_build: u64,
    revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RevocationEntry {
    license_id: String,
    reason: String,
}

#[derive(Debug)]
enum LicenseError {
    Malformed,
    InvalidSignature,
    Revoked,
}

fn verify_blob(blob: &str, pubkey_hex: &str) -> Result<LicensePayload, LicenseError> {
    let (payload_b64, sig_b64) = blob.split_once('.').ok_or(LicenseError::Malformed)?;
    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .map_err(|_| LicenseError::Malformed)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|_| LicenseError::Malformed)?;
    let pubkey_bytes = hex::decode(pubkey_hex).map_err(|_| LicenseError::Malformed)?;
    if pubkey_bytes.len() != 32 {
        return Err(LicenseError::Malformed);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pubkey_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pk).map_err(|_| LicenseError::Malformed)?;
    if sig_bytes.len() != 64 {
        return Err(LicenseError::Malformed);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(&payload_bytes, &signature)
        .map_err(|_| LicenseError::InvalidSignature)?;
    serde_json::from_slice(&payload_bytes).map_err(|_| LicenseError::Malformed)
}

fn is_revoked(license_id: &str, list: &[RevocationEntry]) -> bool {
    list.iter().any(|e| e.license_id == license_id)
}

fn should_accept_update(info: &LicenseInfo, now: u64, build: u64) -> bool {
    if now > info.update_eligible_until {
        return build <= info.last_eligible_build;
    }
    true
}

fn mint_license() -> (String, String) {
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
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    (format!("{payload_b64}.{sig_b64}"), pubkey_hex)
}

#[test]
fn test_license_valid_signature() {
    let (blob, pubkey) = mint_license();
    let payload = verify_blob(&blob, &pubkey).expect("valid signature");
    assert_eq!(payload.license_id, "test-license-1");
}

#[test]
fn test_license_tampered_payload() {
    let (blob, pubkey) = mint_license();
    let mut tampered = blob.clone();
    let bad = if tampered.starts_with('A') { 'B' } else { 'A' };
    tampered.replace_range(0..1, &bad.to_string());
    let result = verify_blob(&tampered, &pubkey);
    assert!(matches!(result, Err(LicenseError::InvalidSignature) | Err(LicenseError::Malformed)));
}

#[test]
fn test_license_tampered_signature() {
    let (blob, pubkey) = mint_license();
    let (payload_b64, _) = blob.split_once('.').unwrap();
    let bad_sig = "A".repeat(86); // ~64 bytes base64
    let tampered = format!("{payload_b64}.{bad_sig}");
    let result = verify_blob(&tampered, &pubkey);
    assert!(matches!(result, Err(LicenseError::InvalidSignature) | Err(LicenseError::Malformed)));
}

#[test]
fn test_license_revoked() {
    let revocations = vec![RevocationEntry {
        license_id: "revoked-1".into(),
        reason: "fraud".into(),
    }];
    assert!(is_revoked("revoked-1", &revocations));
    assert!(!is_revoked("ok-1", &revocations));
}

#[test]
fn test_perpetual_fallback_after_window() {
    let info = LicenseInfo {
        license_id: "x".into(),
        name: "x".into(),
        issued_at: 1,
        update_eligible_until: 1000,
        last_eligible_build: 50,
        revoked: false,
    };
    // Before window: accept.
    assert!(should_accept_update(&info, 500, 999));
    // After window: refuse newer.
    assert!(!should_accept_update(&info, 2000, 60));
    // After window: accept old (perpetual fallback).
    assert!(should_accept_update(&info, 2000, 50));
    assert!(should_accept_update(&info, 2000, 40));
}

#[test]
fn test_expired_update_window_still_runs() {
    let info = LicenseInfo {
        license_id: "x".into(),
        name: "x".into(),
        issued_at: 1,
        update_eligible_until: 1,
        last_eligible_build: 1,
        revoked: false,
    };
    assert!(should_accept_update(&info, 9_999_999, 1));
}

#[test]
fn test_malformed_blob() {
    let result = verify_blob("no-dot-here", &"00".repeat(32));
    assert!(matches!(result, Err(LicenseError::Malformed)));
}
