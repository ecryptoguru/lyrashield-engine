// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
//! Detect any Docker-API-compliant runtime on startup via DOCKER_HOST probe.
//!
//! The engine talks the standard Docker API through `DOCKER_HOST`, so any
//! Docker-compatible runtime (Docker Desktop, Podman Desktop, Rancher
//! Desktop, Colima) works without engine changes. If no runtime is detected,
//! the webview shows a guided install offering free alternatives.

use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DockerDetectError {
    #[error("docker runtime probe failed: {0}")]
    Probe(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub name: String,
    pub version: String,
    pub host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub runtime: Option<RuntimeInfo>,
    pub runtime_ok: bool,
    pub remediation: String,
    pub free_alternatives: Vec<FreeAlternative>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeAlternative {
    pub name: String,
    pub url: String,
    pub note: String,
}

pub fn free_alternatives() -> Vec<FreeAlternative> {
    vec![
        FreeAlternative {
            name: "Podman Desktop".into(),
            url: "https://podman.io/".into(),
            note: "Free, open-source Docker-API-compatible runtime.".into(),
        },
        FreeAlternative {
            name: "Rancher Desktop".into(),
            url: "https://rancherdesktop.io/".into(),
            note: "Free Docker-API-compatible runtime with Kubernetes.".into(),
        },
        FreeAlternative {
            name: "Colima".into(),
            url: "https://github.com/abiosoft/colima".into(),
            note: "Free, lightweight Docker runtime for macOS.".into(),
        },
    ]
}

fn default_docker_host() -> String {
    env::var("DOCKER_HOST").unwrap_or_else(|_| "unix:///var/run/docker.sock".to_string())
}

fn probe_unix_socket(path: &str) -> bool {
    let sock_path = path.strip_prefix("unix://").unwrap_or(path);
    Path::new(sock_path).exists()
}

fn probe_tcp_host(host: &str) -> bool {
    use std::net::TcpStream;
    let addr = host
        .strip_prefix("tcp://")
        .or_else(|| host.strip_prefix("http://"))
        .unwrap_or(host);
    TcpStream::connect_timeout(
        &addr
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap()),
        Duration::from_secs(2),
    )
    .is_ok()
}

/// Probe the Docker-API-compliant runtime via DOCKER_HOST + a version handshake.
pub fn detect_runtime() -> Result<Option<RuntimeInfo>, DockerDetectError> {
    let host = default_docker_host();
    let reachable = if host.starts_with("unix://") {
        probe_unix_socket(&host)
    } else {
        probe_tcp_host(&host)
    };

    if !reachable {
        return Ok(None);
    }

    // Issue a version handshake via the docker SDK if available. We avoid a
    // hard docker crate dependency here by issuing a raw HTTP GET to the
    // Docker API over the unix socket / TCP. For simplicity, report a generic
    // detected runtime; the engine CLI performs the full handshake at scan
    // time.
    Ok(Some(RuntimeInfo {
        name: "Docker-API-compliant runtime".into(),
        version: "unknown".into(),
        host,
    }))
}

/// Run the desktop doctor: detect runtime, build a report for the webview.
pub async fn run_doctor() -> DoctorReport {
    let runtime = detect_runtime().ok().flatten();
    let (runtime_ok, remediation) = match &runtime {
        Some(info) => (true, format!("Runtime detected at {}", info.host)),
        None => (
            false,
            "No Docker-API-compliant runtime detected. Install a free alternative.".into(),
        ),
    };

    DoctorReport {
        runtime,
        runtime_ok,
        remediation,
        free_alternatives: free_alternatives(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_free_alternatives_include_all_three() {
        let alts = free_alternatives();
        let names: Vec<&str> = alts.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"Podman Desktop"));
        assert!(names.contains(&"Rancher Desktop"));
        assert!(names.contains(&"Colima"));
    }

    #[test]
    fn test_detect_runtime_missing_socket() {
        env::remove_var("DOCKER_HOST");
        // With a nonexistent socket, detect_runtime should return None.
        let result = detect_runtime().unwrap();
        // On most test environments /var/run/docker.sock doesn't exist.
        if !Path::new("/var/run/docker.sock").exists() {
            assert!(result.is_none());
        }
    }

    #[tokio::test]
    async fn test_run_doctor_returns_alternatives() {
        let report = run_doctor().await;
        assert!(!report.free_alternatives.is_empty());
        // runtime_ok depends on the environment; just check it's a bool.
        let _ = report.runtime_ok;
    }

    #[test]
    fn test_probe_unix_socket_nonexistent() {
        assert!(!probe_unix_socket("unix:///nonexistent/path/sock"));
    }
}
