// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! LyraShield Local — Tauri desktop shell entry point.
//!
//! Every scan passes a single native license gate (`license::authorize_scan`)
//! before run state is allocated or a provider secret is read. The webview
//! cannot bypass it: scanning, BYOK, and updates are only reachable through
//! the native commands registered here.

#![cfg_attr(not(test), windows_subsystem = "windows")]


use lyrashield_local_lib::scan::Provider;
use lyrashield_local_lib::{docker_detect, keychain, license, scan, sync, updater};

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};

/// Selected BYOK provider + non-secret route metadata (I2). Secret values
/// live only in the OS keychain and are read at spawn time.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ByokConfig {
    pub provider: String, // "chatgpt" | "azure"
    pub azure_endpoint: String,
    pub azure_deployment: String,
}

fn byok_config_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("cannot resolve config dir: {e}"))?;
    Ok(dir.join("byok.json"))
}

fn read_byok_config(app: &tauri::AppHandle) -> Result<ByokConfig, String> {
    let path = byok_config_path(app)?;
    let bytes = std::fs::read(&path).map_err(|_| "no BYOK provider configured".to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| format!("BYOK config is corrupt: {e}"))
}

fn provider_config_from(config: &ByokConfig) -> Result<scan::ProviderRoute, String> {
    match config.provider.as_str() {
        "azure" => Ok(scan::ProviderRoute {
            provider: Provider::Azure,
            azure_endpoint: config.azure_endpoint.clone(),
            azure_deployment: config.azure_deployment.clone(),
        }),
        "chatgpt" => Ok(scan::ProviderRoute {
            provider: Provider::Chatgpt,
            ..Default::default()
        }),
        other => Err(format!("unsupported BYOK provider: {other}")),
    }
}

#[tauri::command]
async fn scan_start(
    app: tauri::AppHandle,
    target: String,
    scan_mode: String,
    max_budget: Option<f64>,
) -> Result<String, String> {
    // Single native license gate (C2): before run state, secrets, or process.
    let licensed = license::authorize_scan()
        .await
        .map_err(|e| format!("scan blocked by license admission: {e}"))?;
    let byok = read_byok_config(&app)?;
    let provider = provider_config_from(&byok)?;
    let _ = licensed;
    scan::start_scan(&app, target, scan_mode, max_budget, provider).await
}

#[tauri::command]
async fn scan_stop() -> Result<(), String> {
    scan::stop_scan().await
}

#[tauri::command]
async fn doctor_run() -> Result<docker_detect::DoctorReport, String> {
    Ok(docker_detect::run_doctor().await)
}

const ALLOWED_KEYCHAIN_KEYS: &[&str] = &[
    "chatgpt-oauth-token",
    "azure-openai-api-key",
    "license-cache",
    "license-id",
    "license-last-validated",
    "machine-id",
];

fn check_keychain_key(key: &str) -> Result<(), String> {
    if ALLOWED_KEYCHAIN_KEYS.contains(&key) {
        Ok(())
    } else {
        Err(format!("key not allowed: {key}"))
    }
}

#[tauri::command]
async fn keychain_get(key: String) -> Result<Option<String>, String> {
    check_keychain_key(&key)?;
    keychain::get(keychain::SERVICE, &key).map_err(|e| e.to_string())
}

/// Save the selected BYOK route (I2): non-secret metadata to the app config
/// file, the Azure key to the keychain only.
#[tauri::command]
async fn byok_save(
    app: tauri::AppHandle,
    config: ByokConfig,
    azure_key: Option<String>,
) -> Result<(), String> {
    match config.provider.as_str() {
        "azure" => {
            if config.azure_endpoint.trim().is_empty()
                || config.azure_deployment.trim().is_empty()
            {
                return Err("Azure BYOK requires an endpoint and a deployment name".into());
            }
            if let Some(key) = azure_key {
                if !key.trim().is_empty() {
                    keychain::set_azure_key(key.trim())
                        .map_err(|e| format!("keychain write failed: {e}"))?;
                }
            }
            let has_key = keychain::get_azure_key()
                .map_err(|e| format!("keychain read failed: {e}"))?
                .is_some_and(|k| !k.trim().is_empty());
            if !has_key {
                return Err("Azure BYOK requires an API key".into());
            }
        }
        "chatgpt" => {
            if !scan::chatgpt_auth_available() {
                return Err(
                    "ChatGPT subscription requires a completed `lyrashield auth login chatgpt` \
                     on this machine"
                        .into(),
                );
            }
        }
        other => return Err(format!("unsupported BYOK provider: {other}")),
    }
    let path = byok_config_path(&app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("cannot create config dir: {e}"))?;
    }
    std::fs::write(&path, serde_json::to_vec(&config).unwrap_or_default())
        .map_err(|e| format!("cannot save BYOK config: {e}"))?;
    Ok(())
}

#[tauri::command]
async fn byok_config(app: tauri::AppHandle) -> Result<ByokConfig, String> {
    read_byok_config(&app)
}

#[tauri::command]
async fn license_activate(
    license_key: String,
) -> Result<license::LicenseInfo, String> {
    license::activate_online(&license_key)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn license_activate_blob(
    blob_b64: String,
    license_id: String,
) -> Result<license::LicenseInfo, String> {
    license::activate(&blob_b64, &license_id).map_err(|e| e.to_string())
}

#[tauri::command]
async fn license_status() -> Result<license::LicenseStatus, String> {
    let local = license::status().map_err(|e| e.to_string())?;
    if local.message.contains("revalidation due") {
        return license::revalidate_online().await.map_err(|e| e.to_string());
    }
    Ok(local)
}

#[tauri::command]
async fn sync_connect(api_key: String) -> Result<sync::SyncState, String> {
    sync::connect(&api_key).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn sync_status() -> Result<sync::SyncState, String> {
    sync::status().await.map_err(|e| e.to_string())
}

/// Native update eligibility + availability (D3): the webview has no
/// downloader permission of its own.
#[tauri::command]
async fn updater_check(app: tauri::AppHandle) -> Result<updater::UpdateInfo, String> {
    updater::check_with_eligibility(&app).await.map_err(|e| e.to_string())
}

/// Download + install an update through the Tauri updater plugin. The
/// plugin's ed25519 verification of the manifest and artifact is the only
/// cryptographic authority; eligibility is re-checked immediately before
/// the offer turns into a download.
#[tauri::command]
async fn updater_install(app: tauri::AppHandle) -> Result<(), String> {
    updater::install_with_verification(&app).await.map_err(|e| e.to_string())
}

pub fn run() {
    env_logger::init();
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            scan_start,
            scan_stop,
            doctor_run,
            keychain_get,
            byok_save,
            byok_config,
            license_activate,
            license_activate_blob,
            license_status,
            sync_connect,
            sync_status,
            updater_check,
            updater_install,
        ])
        .setup(|app| {
            // On startup, detect a Docker-API-compliant runtime. If missing,
            // the webview shows a guided install offering free alternatives.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let report = docker_detect::run_doctor().await;
                let _ = handle.emit("doctor-report", &report);
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running LyraShield Local");
}

fn main() {
    run();
}
