// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! Pure scan-mode and BYOK provider logic (C4, I2) shared by the desktop
//! shell and the standalone test crate.

/// Explicit UI-to-engine scan-mode table (C4). Unsupported modes are
/// unavailable — never silently aliased to another paid mode.
pub fn engine_scan_mode(ui_mode: &str) -> Result<&'static str, String> {
    match ui_mode {
        "QUICK" => Ok("quick"),
        "STANDARD" => Ok("standard"),
        "DEEP" => Ok("deep"),
        other => Err(format!(
            "scan mode {other} is not supported in LyraShield Local; \
             available modes: QUICK, STANDARD, DEEP"
        )),
    }
}

/// The selected BYOK provider for a scan (I2). Exactly one provider's
/// environment reaches the child process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Provider {
    #[default]
    Chatgpt,
    Azure,
}

/// Non-secret BYOK route metadata; secrets are injected by the caller at
/// spawn time (they never appear in this struct, argv, or logs).
#[derive(Debug, Clone, Default)]
pub struct ProviderRoute {
    pub provider: Provider,
    pub azure_endpoint: String,
    pub azure_deployment: String,
}

/// Validate a route and build the environment variables the child receives.
/// `azure_key` and `chatgpt_auth_present` are supplied by the app crate from
/// the OS keychain / engine auth state at spawn time.
pub fn provider_env(
    route: &ProviderRoute,
    azure_key: Option<&str>,
    chatgpt_auth_present: bool,
) -> Result<Vec<(String, String)>, String> {
    match route.provider {
        Provider::Azure => {
            if route.azure_endpoint.trim().is_empty() || route.azure_deployment.trim().is_empty() {
                return Err("Azure BYOK requires an endpoint and a deployment name".into());
            }
            let key = azure_key
                .map(str::trim)
                .filter(|k| !k.is_empty())
                .ok_or("Azure BYOK requires an API key (set it in BYOK setup)")?;
            Ok(vec![
                ("LYRASHIELD_LLM".into(), format!("azure/{}", route.azure_deployment)),
                ("LLM_API_BASE".into(), route.azure_endpoint.trim().to_string()),
                ("LLM_API_KEY".into(), key.to_string()),
            ])
        }
        Provider::Chatgpt => {
            if !chatgpt_auth_present {
                return Err(
                    "ChatGPT subscription requires a completed `lyrashield auth login chatgpt` \
                     on this machine"
                        .into(),
                );
            }
            Ok(vec![("LYRASHIELD_LLM".into(), "chatgpt/gpt-5.6-luna".into())])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_modes_map_explicitly() {
        assert_eq!(engine_scan_mode("QUICK").unwrap(), "quick");
        assert_eq!(engine_scan_mode("STANDARD").unwrap(), "standard");
        assert_eq!(engine_scan_mode("DEEP").unwrap(), "deep");
    }

    #[test]
    fn unsupported_modes_are_unavailable_not_aliased() {
        for mode in ["SAFE", "CUSTOM", "safe", "", "deep", "QUICK ", "../deep"] {
            assert!(engine_scan_mode(mode).is_err(), "{mode} must not map");
        }
    }

    #[test]
    fn azure_route_requires_endpoint_deployment_and_key() {
        let route = ProviderRoute {
            provider: Provider::Azure,
            azure_endpoint: String::new(),
            azure_deployment: "dep".into(),
        };
        assert!(provider_env(&route, Some("k"), true).is_err());
        let route = ProviderRoute {
            provider: Provider::Azure,
            azure_endpoint: "https://x".into(),
            azure_deployment: "dep".into(),
        };
        assert!(provider_env(&route, None, true).is_err());
        let env = provider_env(&route, Some(" secret "), true).unwrap();
        assert_eq!(env[0].1, "azure/dep");
        assert_eq!(env[2].1, "secret"); // trimmed, env-only, never argv
    }

    #[test]
    fn chatgpt_route_requires_auth_state() {
        let route = ProviderRoute::default();
        assert!(provider_env(&route, None, false).is_err());
        let env = provider_env(&route, None, true).unwrap();
        assert_eq!(env[0].1, "chatgpt/gpt-5.6-luna");
    }
}
