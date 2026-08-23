// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

// Shared frontend/native license contract (I3). These shapes mirror the
// Rust structs in desktop/src-tauri/src/license.rs (serde camelCase) and the
// fixtures in desktop/ui/src/fixtures/license-contract.json.
type LicenseInfo = {
  sku: string;
  seatCount: number;
  machineIds: string[];
  updateEligibleUntil: string;
  perpetualFallbackBuild: string | null;
  revoked: boolean;
};

type LicenseStatus = {
  active: boolean;
  info: LicenseInfo | null;
  message: string;
};

export default function LicenseActivation() {
  const [licenseKey, setLicenseKey] = useState("");
  const [blob, setBlob] = useState("");
  const [blobLicenseId, setBlobLicenseId] = useState("");
  const [status, setStatus] = useState<LicenseStatus | null>(null);
  const [error, setError] = useState("");

  const activateOnline = async () => {
    setError("");
    try {
      const info = await invoke<LicenseInfo>("license_activate", {
        licenseKey,
      });
      setStatus({ active: true, info, message: "License active (online activation)." });
    } catch (e) {
      setError(`${e}`);
    }
  };

  const importBlob = async () => {
    setError("");
    try {
      const info = await invoke<LicenseInfo>("license_activate_blob", {
        blobB64: blob,
        licenseId: blobLicenseId,
      });
      setStatus({ active: true, info, message: "License active (offline signed blob)." });
    } catch (e) {
      setError(`${e}`);
    }
  };

  const checkStatus = async () => {
    setError("");
    try {
      const s = await invoke<LicenseStatus>("license_status");
      setStatus(s);
    } catch (e) {
      setError(`${e}`);
    }
  };

  return (
    <div className="panel">
      <h2>License activation</h2>
      <p className="muted">
        Activate online with your license key, or import a signed offline license blob.
        The signature is verified locally (ed25519). Offline grace: your cached license
        works without phoning home for 30 days. Perpetual fallback: the app keeps
        running even after the update window expires.
      </p>

      <h3>Online activation</h3>
      <div className="row">
        <input
          placeholder="License key"
          value={licenseKey}
          onChange={(e) => setLicenseKey(e.target.value)}
          style={{ width: "100%" }}
        />
        <button className="btn-primary" onClick={activateOnline} disabled={!licenseKey}>
          Activate online
        </button>
      </div>

      <h3>Offline signed-blob import</h3>
      <textarea
        placeholder="base64(json).base64(signature)"
        value={blob}
        onChange={(e) => setBlob(e.target.value)}
        rows={4}
        style={{ width: "100%", marginTop: 8 }}
      />
      <div className="row">
        <input
          placeholder="License ID"
          value={blobLicenseId}
          onChange={(e) => setBlobLicenseId(e.target.value)}
        />
        <button onClick={importBlob} disabled={!blob || !blobLicenseId}>
          Import signed blob
        </button>
        <button onClick={checkStatus}>Check status</button>
      </div>

      {status && (
        <div>
          <p className="muted">{status.message}</p>
          {status.info && (
            <p className="muted">
              SKU: {status.info.sku} · seats: {status.info.seatCount}
            </p>
          )}
        </div>
      )}
      {error && <p style={{ color: "var(--danger)" }}>{error}</p>}
    </div>
  );
}
