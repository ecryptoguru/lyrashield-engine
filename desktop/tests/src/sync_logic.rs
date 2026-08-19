// Sync client tests — opt-in gate + entitlement enforced.

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
    struct SyncState {
        connected: bool,
        api_key_set: bool,
        entitlement_ok: bool,
    }

    #[derive(Debug)]
    enum SyncError {
        NotEnabled,
        MissingApiKey,
        EntitlementDenied,
    }

    fn connect(api_key: &str, entitlement_ok: bool) -> Result<SyncState, SyncError> {
        if api_key.is_empty() {
            return Err(SyncError::MissingApiKey);
        }
        Ok(SyncState {
            connected: entitlement_ok,
            api_key_set: true,
            entitlement_ok,
        })
    }

    fn sync_payload(state: &SyncState) -> Result<(), SyncError> {
        if !state.connected || !state.entitlement_ok {
            return Err(SyncError::NotEnabled);
        }
        Ok(())
    }

    #[test]
    fn test_defaults_disconnected() {
        let state = SyncState::default();
        assert!(!state.connected);
        assert!(!state.api_key_set);
    }

    #[test]
    fn test_empty_api_key_rejected() {
        assert!(matches!(connect("", true), Err(SyncError::MissingApiKey)));
    }

    #[test]
    fn test_entitlement_denied() {
        let state = connect("key", false).unwrap();
        assert!(!state.connected);
        assert!(matches!(sync_payload(&state), Err(SyncError::NotEnabled)));
    }

    #[test]
    fn test_entitlement_ok_enables_sync() {
        let state = connect("key", true).unwrap();
        assert!(state.connected);
        assert!(sync_payload(&state).is_ok());
    }

    #[test]
    fn test_sync_requires_opt_in() {
        // Without connect(), nothing syncs.
        let state = SyncState::default();
        assert!(matches!(sync_payload(&state), Err(SyncError::NotEnabled)));
    }
}
