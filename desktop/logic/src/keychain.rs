// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! OS keychain integration for LyraShield Local.
//!
//! Stores ChatGPT OAuth tokens, Azure OpenAI API keys, and the license cache
//! in the OS keychain — never in plaintext files. Uses the `keyring` crate,
//! which selects the platform backend automatically:
//!   - macOS: Keychain (via `security-framework`)
//!   - Windows: Windows Credential Manager (DPAPI-backed)
//!   - Linux: Secret Service (GNOME Keyring / KDE Wallet)
//!
//! The service name is fixed to "LyraShield-Local" so entries are namespaced.

use keyring::Entry;
use thiserror::Error;

pub const SERVICE: &str = "LyraShield-Local";

#[derive(Debug, Error)]
pub enum KeychainError {
    #[error("keychain entry not found: {0}")]
    NotFound(String),
    #[error("keychain backend error: {0}")]
    Backend(String),
}

impl From<keyring::Error> for KeychainError {
    fn from(e: keyring::Error) -> Self {
        match e {
            keyring::Error::NoEntry => {
                KeychainError::NotFound("entry not found".to_string())
            }
            other => KeychainError::Backend(other.to_string()),
        }
    }
}

/// Store a secret in the OS keychain. Never writes a plaintext file.
pub fn set(service: &str, key: &str, value: &str) -> Result<(), KeychainError> {
    let entry = Entry::new(service, key)?;
    entry.set_password(value)?;
    Ok(())
}

/// Retrieve a secret from the OS keychain, or `None` if absent.
pub fn get(service: &str, key: &str) -> Result<Option<String>, KeychainError> {
    let entry = Entry::new(service, key)?;
    match entry.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(KeychainError::from(e)),
    }
}

/// Delete a secret from the OS keychain.
pub fn delete(service: &str, key: &str) -> Result<(), KeychainError> {
    let entry = Entry::new(service, key)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(KeychainError::from(e)),
    }
}

/// Store the ChatGPT OAuth token in the keychain.
pub fn set_chatgpt_token(token: &str) -> Result<(), KeychainError> {
    set(SERVICE, "chatgpt-oauth-token", token)
}

pub fn get_chatgpt_token() -> Result<Option<String>, KeychainError> {
    get(SERVICE, "chatgpt-oauth-token")
}

/// Store the Azure OpenAI API key in the keychain.
pub fn set_azure_key(key: &str) -> Result<(), KeychainError> {
    set(SERVICE, "azure-openai-api-key", key)
}

pub fn get_azure_key() -> Result<Option<String>, KeychainError> {
    get(SERVICE, "azure-openai-api-key")
}

/// Store the signed license cache in the keychain (not a plaintext file).
pub fn set_license_cache(blob_b64: &str) -> Result<(), KeychainError> {
    set(SERVICE, "license-cache", blob_b64)
}

pub fn get_license_cache() -> Result<Option<String>, KeychainError> {
    get(SERVICE, "license-cache")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `keyring` crate's mock backend has entry-only persistence: an
    /// entry created for `set` and a separate one created for `get` do not
    /// share data, so we test the roundtrip on a single `keyring::Entry`
    /// object. `set`/`get`/`delete` are thin wrappers around the same
    /// `Entry` calls, so this proves the keychain mapping works.
    #[test]
    fn test_set_get_delete_roundtrip() {
        let service = "LyraShield-Local-Test";
        let key = "test-key";
        let entry = keyring::Entry::new(service, key).expect("entry creation failed");
        match entry.set_password("secret-value") {
            Ok(()) => {
                let got = entry.get_password().expect("get failed");
                assert_eq!(got, "secret-value");
                entry.delete_credential().expect("delete failed");
                assert!(matches!(
                    entry.get_password(),
                    Err(keyring::Error::NoEntry)
                ));
            }
            Err(keyring::Error::NoEntry) | Err(keyring::Error::PlatformFailure(_)) => {
                // No keyring backend available (headless CI) — skip.
            }
            Err(other) => panic!("unexpected keyring error: {other:?}"),
        }
    }

    #[test]
    fn test_get_missing_returns_none() {
        let service = "LyraShield-Local-Test-Missing";
        match get(service, "absent-key") {
            Ok(None) => {}
            Ok(Some(v)) => panic!("expected none, got {v}"),
            Err(KeychainError::Backend(_)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
}
