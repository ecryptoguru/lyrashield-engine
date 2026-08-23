// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! Scan lifecycle — license admission, supervised engine subprocess, streaming.
//!
//! The engine runs as a bundled sidecar binary (never a global `PATH` lookup
//! in release builds), receives only the selected BYOK provider's secrets via
//! environment variables, and is owned by one supervisor: `stop_scan` kills
//! and awaits the exact owned child before reporting the stop.

use crate::keychain;
pub use lyrashield_desktop_logic::scan_modes::{
    engine_scan_mode, provider_env, Provider, ProviderRoute,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::oneshot;

#[derive(Debug, Default)]
pub struct ScanState {
    pub running: bool,
    pub run_id: Option<String>,
    pub cancel: Option<oneshot::Sender<()>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgressEvent {
    pub stream: String,
    pub line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDoneEvent {
    pub run_id: String,
    pub success: bool,
    pub code: Option<i32>,
    pub cancelled: bool,
}

/// Whether the engine's ChatGPT subscription auth state exists on this
/// machine (the supported authentication state for the ChatGPT BYOK route).
pub fn chatgpt_auth_available() -> bool {
    chatgpt_auth_path().is_file()
}

/// Engine subscription-auth store (managed by `lyrashield auth login chatgpt`).
fn chatgpt_auth_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    PathBuf::from(home)
        .join(".strix")
        .join("subscription-auth.json")
}

/// Resolve the engine executable (I18).
///
/// Release builds must launch the bundled, version-matched sidecar shipped
/// next to the app executable — a global `PATH` install is never used. Debug
/// builds may explicitly point at a developer engine via
/// `LYRASHIELD_ENGINE_BIN`.
pub fn resolve_engine_bin() -> Result<PathBuf, String> {
    if cfg!(debug_assertions) {
        if let Ok(dev) = std::env::var("LYRASHIELD_ENGINE_BIN") {
            if !dev.trim().is_empty() {
                return Ok(PathBuf::from(dev));
            }
        }
    }
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate app bundle: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "cannot locate app bundle directory".to_string())?;
    let base = "lyrashield-engine";
    let names = if cfg!(target_os = "windows") {
        vec![
            "lyrashield-engine.exe",
            "lyrashield-engine-x86_64-pc-windows-msvc.exe",
            "lyrashield-engine-aarch64-pc-windows-msvc.exe",
            base,
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            base,
            "lyrashield-engine-universal-apple-darwin",
            "lyrashield-engine-aarch64-apple-darwin",
            "lyrashield-engine-x86_64-apple-darwin",
        ]
    } else {
        vec![
            base,
            "lyrashield-engine-x86_64-unknown-linux-gnu",
            "lyrashield-engine-aarch64-unknown-linux-gnu",
        ]
    };
    // Bundled as a resource: next to the executable on Windows/Linux, and in
    // ../Resources inside a macOS .app bundle.
    let mut candidates = Vec::with_capacity(names.len() * 2);
    for name in &names {
        candidates.push(dir.join(name));
        candidates.push(dir.join("../Resources").join(name));
    }
    let sidecar = candidates
        .iter()
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            "bundled engine sidecar not found — reinstall LyraShield Local \
             (the app cannot fall back to a global lyrashield install)"
                .to_string()
        })?;
    Ok(sidecar.clone())
}

/// Startup version handshake: the bundled sidecar must execute and report a
/// version matching the desktop shell. A mismatched or missing sidecar blocks
/// scans with an actionable error instead of silently running a different
/// engine.
pub async fn engine_sidecar_version(bin: &PathBuf) -> Result<String, String> {
    let expected = env!("CARGO_PKG_VERSION");
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(bin)
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "bundled engine version handshake timed out".to_string())?
    .map_err(|e| format!("bundled engine failed to start: {e}"))?;
    if !out.status.success() {
        return Err("bundled engine version check failed".into());
    }
    let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let version = raw
        .strip_prefix("lyrashield ")
        .unwrap_or(&raw)
        .trim()
        .to_string();
    if version.is_empty() {
        return Err("bundled engine reported no version".into());
    }
    if version != expected {
        return Err(format!(
            "bundled engine version {version} does not match shell version {expected}"
        ));
    }
    Ok(version)
}

/// Shared scan supervisor state.
pub struct ScanSupervisor {
    pub state: Arc<Mutex<ScanState>>,
}

impl Default for ScanSupervisor {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(ScanState::default())),
        }
    }
}

static SUPERVISOR: std::sync::OnceLock<ScanSupervisor> = std::sync::OnceLock::new();

/// The process-wide scan supervisor.
pub fn supervisor() -> &'static ScanSupervisor {
    SUPERVISOR.get_or_init(ScanSupervisor::default)
}

/// Start a scan: license admission happens in the `scan_start` command before
/// this function reserves any run state. Spawns the bundled engine with only
/// the selected provider's environment and streams progress while it runs.
pub async fn start_scan(
    app: &AppHandle,
    target: String,
    ui_scan_mode: String,
    max_budget: Option<f64>,
    provider: ProviderRoute,
) -> Result<String, String> {
    let engine_mode = engine_scan_mode(&ui_scan_mode)?;
    let bin = resolve_engine_bin()?;
    let version = engine_sidecar_version(&bin).await?;
    let env = provider_env(
        &provider,
        keychain::get_azure_key().ok().flatten().as_deref(),
        chatgpt_auth_available(),
    )?;

    let run_id = format!("local-{}", chrono_like_ts());
    let cancel = {
        let supervisor = supervisor().state.clone();
        let mut state = supervisor.lock().unwrap();
        if state.running {
            return Err("a scan is already running".into());
        }
        state.running = true;
        state.run_id = Some(run_id.clone());
        let (tx, rx) = oneshot::channel::<()>();
        state.cancel = Some(tx);
        rx
    };

    let app_handle = app.clone();
    let run_id_for_task = run_id.clone();
    let supervisor_state = supervisor().state.clone();
    tokio::spawn(async move {
        let mut argv = vec![
            "--target".to_string(),
            target,
            "--scan-mode".to_string(),
            engine_mode.to_string(),
            "--non-interactive".to_string(),
        ];
        if let Some(budget) = max_budget {
            argv.push("--max-budget".to_string());
            argv.push(budget.to_string());
        }

        let mut command = Command::new(&bin);
        command
            .args(&argv)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for (key, value) in env {
            command.env(key, value);
        }

        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = app_handle.emit(
                    "scan-progress",
                    ScanProgressEvent {
                        stream: "stderr".into(),
                        line: format!("failed to start bundled engine: {e}"),
                    },
                );
                let _ = app_handle.emit(
                    "scan-done",
                    ScanDoneEvent {
                        run_id: run_id_for_task.clone(),
                        success: false,
                        code: None,
                        cancelled: false,
                    },
                );
                clear_state_if_current(&supervisor_state, &run_id_for_task);
                return;
            }
        };

        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");

        let app_out = app_handle.clone();
        let out_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let _ = app_out.emit(
                    "scan-progress",
                    ScanProgressEvent {
                        stream: "stdout".into(),
                        line,
                    },
                );
            }
        });

        let app_err = app_handle.clone();
        let err_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let _ = app_err.emit(
                    "scan-progress",
                    ScanProgressEvent {
                        stream: "stderr".into(),
                        line,
                    },
                );
            }
        });

        // M1: progress events flow while the child runs; the pipe tasks above
        // stream concurrently with the wait below rather than after it.
        let mut cancel_rx = cancel;
        let cancelled_via_stop = &mut cancel_rx;
        #[allow(unused_assignments)]
        let mut exit_is_cancelled = false;
        let exit = tokio::select! {
            status = child.wait() => status,
            received = cancelled_via_stop => {
                exit_is_cancelled = received.is_ok();
                // Stop: kill and AWAIT the exact owned child before telling
                // the UI the scan stopped (I1).
                let _ = child.kill().await;
                child.wait().await
            }
        };
        drop(cancel_rx);

        let _ = tokio::join!(out_task, err_task);

        let cancelled = exit_is_cancelled;
        let (success, code) = match exit {
            Ok(s) => (s.success(), s.code()),
            Err(_) => (false, None),
        };

        let _ = app_handle.emit(
            "scan-done",
            ScanDoneEvent {
                run_id: run_id_for_task.clone(),
                success: success && !cancelled,
                code,
                cancelled,
            },
        );

        clear_state_if_current(&supervisor_state, &run_id_for_task);
        let _ = version; // recorded for diagnostics; handshake already ran
    });

    Ok(run_id)
}

/// Stop the running scan (I1). Idempotent; never clears a newer run's state.
pub async fn stop_scan() -> Result<(), String> {
    let sender = {
        let supervisor = supervisor().state.clone();
        let mut state = supervisor.lock().unwrap();
        if !state.running {
            return Ok(());
        }
        state.cancel.take()
    };
    // Sending signals the runner task to kill + await the child; the
    // scan-done event with cancelled=true is emitted only after the process
    // is gone. A second stop while the first is in flight is a no-op.
    if let Some(tx) = sender {
        let _ = tx.send(());
    }
    Ok(())
}

/// Clear supervisor state only when it still describes `run_id` — a newer
/// run started in the meantime keeps its own state (I1).
fn clear_state_if_current(state: &Arc<Mutex<ScanState>>, run_id: &str) {
    let mut state = state.lock().unwrap();
    if state.run_id.as_deref() == Some(run_id) {
        state.running = false;
        state.run_id = None;
        state.cancel = None;
    }
}

/// A simple monotonic-ish timestamp without pulling in chrono.
fn chrono_like_ts() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_requires_endpoint_deployment_and_key() {
        let route = ProviderRoute {
            provider: Provider::Azure,
            azure_endpoint: String::new(),
            azure_deployment: "dep".into(),
        };
        assert!(provider_env(&route, Some("k"), true).is_err());
    }
}
