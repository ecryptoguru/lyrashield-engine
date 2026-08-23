// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import ByokSetup from "./screens/ByokSetup";
import LicenseActivation from "./screens/LicenseActivation";
import Settings from "./screens/Settings";
import UpdatePrompt from "./screens/UpdatePrompt";

type Tab = "scan" | "byok" | "license" | "settings" | "update";

const EDITION_LABEL = "LyraShield Desktop — Local edition";

export default function App() {
  const [tab, setTab] = useState<Tab>("scan");
  const [target, setTarget] = useState("");
  const [scanMode, setScanMode] = useState("STANDARD");
  const [maxBudget, setMaxBudget] = useState("");
  const [progress, setProgress] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [findings, setFindings] = useState<string[]>([]);
  const [doctor, setDoctor] = useState<string>("");

  useEffect(() => {
    const unlistenProgress = listen<{ stream: string; line: string }>(
      "scan-progress",
      (e) => {
        setProgress((prev) => [...prev, `[${e.payload.stream}] ${e.payload.line}`]);
      }
    );
    const unlistenDone = listen<{
      run_id: string;
      success: boolean;
      cancelled: boolean;
    }>("scan-done", (e) => {
      setRunning(false);
      setFindings((prev) => [
        ...prev,
        e.payload.cancelled
          ? `Scan cancelled (run ${e.payload.run_id}).`
          : `Scan ${e.payload.success ? "completed" : "failed"} (run ${e.payload.run_id}).`,
      ]);
    });
    const unlistenDoctor = listen<{ runtime_ok: boolean; remediation: string }>(
      "doctor-report",
      (e) => {
        setDoctor(
          e.payload.runtime_ok
            ? "Docker-API-compliant runtime detected."
            : `No runtime detected. ${e.payload.remediation}`
        );
      }
    );
    return () => {
      unlistenProgress.then((f) => f());
      unlistenDone.then((f) => f());
      unlistenDoctor.then((f) => f());
    };
  }, []);

  const startScan = async () => {
    if (!target) return;
    setProgress([]);
    setFindings([]);
    setRunning(true);
    try {
      await invoke("scan_start", {
        target,
        scanMode,
        maxBudget: maxBudget ? parseFloat(maxBudget) : null,
      });
    } catch (e) {
      setRunning(false);
      setProgress((prev) => [...prev, `[error] ${e}`]);
    }
  };

  const stopScan = async () => {
    await invoke("scan_stop");
    setRunning(false);
  };

  const runDoctor = async () => {
    const report = await invoke<{ runtime_ok: boolean; remediation: string }>("doctor_run");
    setDoctor(
      report.runtime_ok
        ? "Docker-API-compliant runtime detected."
        : `No runtime detected. ${report.remediation}`
    );
  };

  return (
    <div className="app">
      <div className="header">
        <h1>LyraShield Local</h1>
        <span className="edition">{EDITION_LABEL}</span>
      </div>

      <div className="tabs">
        {(["scan", "byok", "license", "settings", "update"] as Tab[]).map((t) => (
          <div
            key={t}
            className={`tab ${tab === t ? "active" : ""}`}
            onClick={() => setTab(t)}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </div>
        ))}
      </div>

      {tab === "scan" && (
        <>
          <div className="panel">
            <h2>1. Point at a project</h2>
            <input
              placeholder="/path/to/repo or https://github.com/you/repo"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              style={{ width: "100%" }}
            />
          </div>

          <div className="panel">
            <h2>2. Pick a scan mode (all depths available locally)</h2>
            <select value={scanMode} onChange={(e) => setScanMode(e.target.value)}>
              {["QUICK", "STANDARD", "DEEP"].map((m) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          </div>

          <div className="panel">
            <h2>3. Run scan</h2>
            <div className="row">
              <input
                placeholder="Max budget USD (optional)"
                value={maxBudget}
                onChange={(e) => setMaxBudget(e.target.value)}
              />
              <button className="btn-primary" onClick={startScan} disabled={running || !target}>
                {running ? "Scanning…" : "Run scan"}
              </button>
              <button className="btn-danger" onClick={stopScan} disabled={!running}>
                Stop
              </button>
              <button onClick={runDoctor}>Doctor</button>
            </div>
            {doctor && <p className="muted">{doctor}</p>}
            <div className="progress">
              {progress.length === 0 ? "No output yet." : progress.join("\n")}
            </div>
          </div>

          <div className="panel">
            <h2>4. Findings + fix suggestions</h2>
            <div className="findings">
              {findings.length === 0 ? (
                <p className="muted">No findings yet — run a scan.</p>
              ) : (
                findings.map((f, i) => <div key={i} className="finding">{f}</div>)
              )}
            </div>
            <div className="row">
              <button>Export SARIF</button>
              <button>Export report</button>
            </div>
          </div>
        </>
      )}

      {tab === "byok" && <ByokSetup />}
      {tab === "license" && <LicenseActivation />}
      {tab === "settings" && <Settings />}
      {tab === "update" && <UpdatePrompt />}
    </div>
  );
}
