// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! Scan lifecycle — spawn the engine CLI as a subprocess, stream stdout/stderr
//! to the webview via Tauri events, and handle start/stop/progress.
//!
//! The engine CLI binary is `lyrashield`. We spawn it with the standard run
//! contract (`--target`, `--scan-mode`, `--max-budget`, `--non-interactive`).
//! All scan depths are available locally; no agent-minute metering.

use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[derive(Debug, Clone, Default)]
pub struct ScanState {
    pub running: bool,
    pub run_id: Option<String>,
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
}

/// Start a scan by spawning the engine CLI. Streams progress to the webview.
pub async fn start_scan(
    app: &AppHandle,
    target: String,
    scan_mode: String,
    max_budget: Option<f64>,
) -> Result<String, String> {
    let run_id = format!("local-{}", chrono_like_ts());

    {
        let mut state = crate::state().scan.lock().unwrap();
        if state.running {
            return Err("a scan is already running".into());
        }
        state.running = true;
        state.run_id = Some(run_id.clone());
    }

    let app_handle = app.clone();
    let run_id_for_task = run_id.clone();
    tokio::spawn(async move {
        let mut argv = vec![
            "lyrashield".to_string(),
            "--target".to_string(),
            target,
            "--scan-mode".to_string(),
            scan_mode,
            "--non-interactive".to_string(),
        ];
        if let Some(budget) = max_budget {
            argv.push("--max-budget".to_string());
            argv.push(budget.to_string());
        }

        let mut child = match Command::new(&argv[0])
            .args(&argv[1..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                let _ = app_handle.emit(
                    "scan-done",
                    ScanDoneEvent {
                        run_id: run_id_for_task,
                        success: false,
                        code: None,
                    },
                );
                let _ = app_handle.emit(
                    "scan-progress",
                    ScanProgressEvent {
                        stream: "stderr".into(),
                        line: format!("failed to start engine CLI: {e}"),
                    },
                );
                let mut state = crate::state().scan.lock().unwrap();
                state.running = false;
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

        let _ = tokio::join!(out_task, err_task);

        let status = child.wait().await;
        let (success, code) = match status {
            Ok(s) => (s.success(), s.code()),
            Err(_) => (false, None),
        };

        let _ = app_handle.emit(
            "scan-done",
            ScanDoneEvent {
                run_id: run_id_for_task.clone(),
                success,
                code,
            },
        );

        let mut state = crate::state().scan.lock().unwrap();
        state.running = false;
    });

    Ok(run_id)
}

/// Stop the running scan (if any). The child process is killed on drop via
/// `kill_on_drop(true)`.
pub async fn stop_scan() -> Result<(), String> {
    let mut state = crate::state().scan.lock().unwrap();
    state.running = false;
    state.run_id = None;
    Ok(())
}

/// A simple monotonic-ish timestamp without pulling in chrono.
fn chrono_like_ts() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
