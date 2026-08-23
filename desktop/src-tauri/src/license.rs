// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! License cache + online activation/revalidation for LyraShield Local.
//!
//! Signature verification, admission rules, revocation, and perpetual
//! fallback live in the shared `lyrashield-desktop-logic` crate; this module
//! owns the keychain-backed cache and the online flows.
//!
//! Offline grace: honor a cached signed license without phoning home.
//! Perpetual fallback: track the last-eligible-build; refuse newer updates
//! after `update_eligible_until` but never deactivate the app.
//! Revocation: a bundled revocation list (shipped with signed updates)
//! refuses scans and shows a message.
//!
//! The license blob is a base64-encoded JSON payload + ed25519 signature:
//!   `<base64(json_payload)>.<base64(signature)>`
//! The signature is verified against the bundled ed25519 public key. The
//! license cache is stored in the OS keychain (never plaintext).

use lyrashield_desktop_logic::license::{
    admission_decision, bundled_revocation_list, is_revoked, verify_blob, LicenseError,
    LAST_VALIDATED_KEY, MACHINE_ID_KEY, OFFLINE_GRACE_SECS,
};

pub use lyrashield_desktop_logic::license::{
    should_accept_update, LicenseInfo, LicensePayload, LicenseStatus, RevocationEntry,
    DEFAULT_API_BASE, LICENSE_CACHE_KEY,
};

use crate::keychain;

/// Bundled ed25519 public key for license verification.
///
/// Dev/test default is 32 zero bytes so unit tests can mint their own pair.
/// Release builds (`--release`, or `LYRASHIELD_RELEASE=1`) MUST inject the
/// real public half via `LYRASHIELD_LICENSE_PUBKEY_HEX` at compile time.
/// The private half never lives in this repo.
pub const BUNDLED_PUBKEY_HEX: &str = match option_env!("LYRASHIELD_LICENSE_PUBKEY_HEX") {
    Some(hex) => hex,
    None => "0000000000000000000000000000000000000000000000000000000000000000",
};

const ZERO_PUBKEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Hex of the pubkey this binary will actually verify against.
/// Release builds refuse the all-zero placeholder.
pub fn bundled_pubkey_hex() -> &'static str {
    let release = cfg!(not(debug_assertions))
        || std::env::var("LYRASHIELD_RELEASE").ok().as_deref() == Some("1");
    if release && BUNDLED_PUBKEY_HEX == ZERO_PUBKEY_HEX {
        panic!(
            "LYRASHIELD_LICENSE_PUBKEY_HEX is unset in a release build.              Inject the real public key at compile time; do not ship the zero placeholder."
        );
    }
    BUNDLED_PUBKEY_HEX
}

/// Cache a verified blob + stamp last-validated-at (unix seconds).
fn cache_verified(blob: &str, license_id: &str) -> Result<(), LicenseError> {
    let now = unix_now();
    keychain::set_license_cache(blob).map_err(LicenseError::from)?;
    keychain::set(keychain::SERVICE, "license-id", license_id).map_err(LicenseError::from)?;
    keychain::set(keychain::SERVICE, LAST_VALIDATED_KEY, &now.to_string())
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
    if let Some(existing) =
        keychain::get(keychain::SERVICE, MACHINE_ID_KEY).map_err(LicenseError::from)?
    {
        if !existing.is_empty() {
            return Ok(existing);
        }
    }
    let id = format!("ls-{}", hex::encode(rand::random::<[u8; 16]>()));
    keychain::set(keychain::SERVICE, MACHINE_ID_KEY, &id).map_err(LicenseError::from)?;
    Ok(id)
}

/// Activate a license from an already-signed detached blob (offline / tests).
/// Production activation goes through [`activate_online`].
pub fn activate(blob_b64: &str, license_id: &str) -> Result<LicenseInfo, LicenseError> {
    let payload = lyrashield_desktop_logic::license::verify_and_check_revoked(
        blob_b64,
        license_id,
        &bundled_pubkey_hex(),
        &bundled_revocation_list(),
    )?;
    let this_machine = machine_id()?;
    if !payload.machine_ids.is_empty() && !payload.machine_ids.iter().any(|m| m == &this_machine) {
        return Err(LicenseError::InvalidPayload(
            "license is not issued for this machine".into(),
        ));
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

fn clear_cached_license() {
    let _ = keychain::delete(keychain::SERVICE, "license-cache");
    let _ = keychain::delete(keychain::SERVICE, "license-id");
    let _ = keychain::delete(keychain::SERVICE, LAST_VALIDATED_KEY);
}

fn revoked_status() -> LicenseStatus {
    LicenseStatus {
        active: false,
        info: None,
        message: "License revoked — contact support.".into(),
        needs_revalidation: false,
    }
}

/// Read the last successful online-validation stamp (unix seconds).
fn last_validated_stamp() -> u64 {
    keychain::get(keychain::SERVICE, LAST_VALIDATED_KEY)
        .ok()
        .flatten()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Read the cached license status. Never phones home for the crypto check.
/// After OFFLINE_GRACE_SECS the caller should run [`revalidate_online`].
pub fn status() -> Result<LicenseStatus, LicenseError> {
    let cached = keychain::get_license_cache().map_err(LicenseError::from)?;
    match cached {
        None => Ok(LicenseStatus {
            active: false,
            info: None,
            message: "No license activated.".into(),
            needs_revalidation: false,
        }),
        Some(blob) => {
            let payload = verify_blob(&blob, bundled_pubkey_hex())?;
            let license_id = match keychain::get(keychain::SERVICE, "license-id") {
                Ok(Some(id)) if !id.is_empty() => id,
                Ok(_) => {
                    clear_cached_license();
                    return Ok(LicenseStatus {
                        active: false,
                        info: None,
                        message: "License cache is incomplete — activate again.".into(),
                        needs_revalidation: false,
                    });
                }
                Err(e) => return Err(LicenseError::from(e)),
            };
            let revocations = bundled_revocation_list();
            if is_revoked(&license_id, &revocations) {
                clear_cached_license();
                return Ok(revoked_status());
            }
            let last = last_validated_stamp();
            let age = unix_now().saturating_sub(last);
            let needs_revalidation = last == 0 || age > OFFLINE_GRACE_SECS;
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
                message: if needs_revalidation {
                    "License active — revalidation due.".into()
                } else {
                    "License active (offline grace).".into()
                },
                needs_revalidation,
            })
        }
    }
}

/// Online revalidation. Revoke is not expiry: a revoked license is a hard
/// stop (cache cleared). Network failure during grace keeps the cached
/// license so a laptop on a plane still scans.
pub async fn revalidate_online() -> Result<LicenseStatus, LicenseError> {
    let license_id = match keychain::get(keychain::SERVICE, "license-id") {
        Ok(Some(id)) if !id.is_empty() => id,
        _ => {
            clear_cached_license();
            return Ok(LicenseStatus {
                active: false,
                info: None,
                message: "License cache is incomplete — activate again.".into(),
                needs_revalidation: false,
            });
        }
    };
    let api_base =
        std::env::var("LYRASHIELD_API_URL").unwrap_or_else(|_| DEFAULT_API_BASE.to_string());
    let url = format!("{}/api/licenses/verify", api_base.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .user_agent("LyraShield-Local")
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| LicenseError::Request(e.to_string()))?;
    let resp = match client
        .post(url)
        .json(&serde_json::json!({ "licenseId": license_id }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return status(),
    };
    if !resp.status().is_success() {
        // Do not refresh LAST_VALIDATED_KEY on 4xx/5xx.
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        let revoked = body.pointer("/data/revoked").and_then(|v| v.as_bool()) == Some(true)
            || body.pointer("/data/reason").and_then(|v| v.as_str()) == Some("LICENSE_REVOKED")
            || body.pointer("/error/code").and_then(|v| v.as_str()) == Some("LICENSE_REVOKED");
        if revoked {
            clear_cached_license();
            return Ok(revoked_status());
        }
        return status();
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(_) => return status(),
    };
    let revoked = body.pointer("/data/revoked").and_then(|v| v.as_bool()) == Some(true)
        || body.pointer("/data/reason").and_then(|v| v.as_str()) == Some("LICENSE_REVOKED");
    if revoked {
        clear_cached_license();
        return Ok(revoked_status());
    }
    let valid = body.pointer("/data/valid").and_then(|v| v.as_bool()) == Some(true);
    if !valid {
        return status();
    }
    if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        let _ = keychain::set(keychain::SERVICE, LAST_VALIDATED_KEY, &now.as_secs().to_string());
    }
    status()
}

/// Native license admission for scans (C2): every scan path funnels through
/// here before any run state is allocated, secrets are read, or a child
/// process is spawned. Fails closed for missing, malformed, revoked,
/// wrong-machine, unvalidated, and grace-expired licenses.
///
/// Offline behavior: a previously verified license may scan during the
/// bounded grace window while revalidation is unavailable; after grace, a
/// successful online proof is required. A definitive revocation response
/// invalidates immediately in both cases.
pub async fn authorize_scan() -> Result<LicenseInfo, LicenseError> {
    let mut current = status()?;
    if !current.active {
        return Err(LicenseError::InvalidPayload(current.message));
    }
    if current.needs_revalidation {
        current = revalidate_online().await?;
    }
    admission_decision(current.active, &current.message, last_validated_stamp(), unix_now())
        .map_err(LicenseError::InvalidPayload)?;
    let info = current
        .info
        .ok_or_else(|| LicenseError::InvalidPayload("license state incomplete".into()))?;
    let this_machine = machine_id()?;
    if !info.machine_ids.is_empty() && !info.machine_ids.iter().any(|m| m == &this_machine) {
        return Err(LicenseError::InvalidPayload(
            "license is not issued for this machine".into(),
        ));
    }
    Ok(info)
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
    let api_base =
        std::env::var("LYRASHIELD_API_URL").unwrap_or_else(|_| DEFAULT_API_BASE.to_string());
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
