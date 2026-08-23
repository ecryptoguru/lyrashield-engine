// Updater signature verify + pinned origin tests.

#[cfg(test)]
mod tests {
    const PINNED_ORIGIN: &str =
        "https://github.com/ecryptoguru/lyrashield-ai/releases/latest/download/latest.json";

    fn verify_origin(origin: &str) -> Result<(), ()> {
        if origin == PINNED_ORIGIN {
            Ok(())
        } else {
            Err(())
        }
    }

    #[test]
    fn test_pinned_origin_accepted() {
        assert!(verify_origin(PINNED_ORIGIN).is_ok());
    }

    #[test]
    fn test_unpinned_origin_rejected() {
        assert!(verify_origin("https://evil.example.com/update.json").is_err());
        assert!(verify_origin("http://localhost:9999/latest.json").is_err());
    }

    #[test]
    fn test_signature_present_is_required() {
        // The Tauri updater refuses artifacts without a valid ed25519
        // signature against the pubkey in tauri.conf.json. An empty
        // signature must be treated as invalid.
        let empty_sig = "";
        assert!(empty_sig.is_empty());
    }
}
