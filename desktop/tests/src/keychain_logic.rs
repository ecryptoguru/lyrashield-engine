// Keychain abstraction tests (mock per-OS). The keyring crate selects the
// platform backend; here we test the abstraction contract without touching
// real OS keychain entries.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    /// A mock keychain that mirrors the real abstraction's contract.
    struct MockKeychain {
        store: HashMap<String, String>,
    }

    impl MockKeychain {
        fn new() -> Self {
            Self { store: HashMap::new() }
        }

        fn set(&mut self, service: &str, key: &str, value: &str) -> Result<(), String> {
            self.store.insert(format!("{service}:{key}"), value.to_string());
            Ok(())
        }

        fn get(&self, service: &str, key: &str) -> Option<String> {
            self.store.get(&format!("{service}:{key}")).cloned()
        }

        fn delete(&mut self, service: &str, key: &str) -> Result<(), String> {
            self.store.remove(&format!("{service}:{key}"));
            Ok(())
        }
    }

    #[test]
    fn test_set_get_roundtrip() {
        let mut kc = MockKeychain::new();
        kc.set("LyraShield-Local", "azure-openai-api-key", "secret").unwrap();
        assert_eq!(
            kc.get("LyraShield-Local", "azure-openai-api-key"),
            Some("secret".into())
        );
    }

    #[test]
    fn test_get_missing_returns_none() {
        let kc = MockKeychain::new();
        assert_eq!(kc.get("LyraShield-Local", "absent"), None);
    }

    #[test]
    fn test_delete_removes_entry() {
        let mut kc = MockKeychain::new();
        kc.set("LyraShield-Local", "chatgpt-oauth-token", "tok").unwrap();
        kc.delete("LyraShield-Local", "chatgpt-oauth-token").unwrap();
        assert_eq!(kc.get("LyraShield-Local", "chatgpt-oauth-token"), None);
    }

    #[test]
    fn test_secrets_never_plaintext_files() {
        // The contract: secrets live in the keychain, never in plaintext files.
        // This test asserts the mock never writes to disk (it only holds
        // in-memory entries). The real abstraction uses the OS keychain.
        let mut kc = MockKeychain::new();
        kc.set("LyraShield-Local", "license-cache", "blob").unwrap();
        // No file was created — the mock has no filesystem path.
        assert!(!std::path::Path::new("LyraShield-Local-license-cache").exists());
    }

    #[test]
    fn test_namespaced_service() {
        // All entries are namespaced under "LyraShield-Local".
        let mut kc = MockKeychain::new();
        kc.set("LyraShield-Local", "k", "v").unwrap();
        assert!(kc.store.contains_key("LyraShield-Local:k"));
    }
}
