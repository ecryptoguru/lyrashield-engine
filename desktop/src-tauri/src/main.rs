// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! LyraShield Local — Tauri desktop shell entry point.
//!
//! Spawns the engine CLI as a subprocess, streams stdout/stderr to the
//! webview via Tauri events, and manages the local results store path.
//! Credentials live in the OS keychain (never plaintext files).

#![cfg_attr(not(test), windows_subsystem = "windows")]

mod docker_detect;
mod keychain;
mod license;
mod scan;
mod sync;
mod updater;

use std::sync::Mutex;
use std::sync::OnceLock;

use tauri::Manager;

/// Global scan state shared across Tauri commands.
pub struct AppState {
    pub scan: Mutex<scan::ScanState>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            scan: Mutex::new(scan::ScanState::default()),
        }
    }
}

static STATE: OnceLock<AppState> = OnceLock::new();

pub fn state() -> &'static AppState {
    STATE.get_or_init(AppState::default)
}

/// Emit a scan progress event to the webview.
#[tauri::command]
async fn scan_start(
    app: tauri::AppHandle,
    target: String,
    scan_mode: String,
    max_budget: Option<f64>,
) -> Result<String, String> {
    scan::start_scan(&app, target, scan_mode, max_budget).await
}

#[tauri::command]
async fn scan_stop() -> Result<(), String> {
    scan::stop_scan().await
}

#[tauri::command]
async fn doctor_run() -> Result<docker_detect::DoctorReport, String> {
    docker_detect::run_doctor().await
}

#[tauri::command]
async fn keychain_set(service: String, key: String, value: String) -> Result<(), String> {
    keychain::set(&service, &key, &value).map_err(|e| e.to_string())
}

#[tauri::command]
async fn keychain_get(service: String, key: String) -> Result<Option<String>, String> {
    keychain::get(&service, &key).map_err(|e| e.to_string())
}

#[tauri::command]
async fn license_activate(blob_b64: String) -> Result<license::LicenseInfo, String> {
    license::activate(&blob_b64).map_err(|e| e.to_string())
}

#[tauri::command]
async fn license_status() -> Result<license::LicenseStatus, String> {
    license::status().map_err(|e| e.to_string())
}

#[tauri::command]
async fn sync_connect(api_key: String) -> Result<sync::SyncState, String> {
    sync::connect(&api_key).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn sync_status() -> Result<sync::SyncState, String> {
    sync::status().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn updater_check() -> Result<updater::UpdateInfo, String> {
    updater::check().await.map_err(|e| e.to_string())
}

pub fn run() {
    env_logger::init();
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .invoke_handler(tauri::generate_handler![
            scan_start,
            scan_stop,
            doctor_run,
            keychain_set,
            keychain_get,
            license_activate,
            license_status,
            sync_connect,
            sync_status,
            updater_check,
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
