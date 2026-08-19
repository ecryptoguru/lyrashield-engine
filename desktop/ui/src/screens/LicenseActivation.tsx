// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type LicenseInfo = {
  license_id: string;
  name: string;
  issued_at: number;
  update_eligible_until: number;
  last_eligible_build: number;
  revoked: boolean;
};

type LicenseStatus = {
  active: boolean;
  info: LicenseInfo | null;
  message: string;
};

export default function LicenseActivation() {
  const [blob, setBlob] = useState("");
  const [status, setStatus] = useState<LicenseStatus | null>(null);
  const [error, setError] = useState("");

  const activate = async () => {
    setError("");
    try {
      const info = await invoke<LicenseInfo>("license_activate", { blobB64: blob });
      setStatus({ active: true, info, message: "License active (offline grace)." });
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
        Paste your signed license blob. The signature is verified locally (ed25519).
        Offline grace: your cached license works without phoning home. Perpetual fallback:
        the app keeps running even after the update window expires.
      </p>
      <textarea
        placeholder="base64(json).base64(signature)"
        value={blob}
        onChange={(e) => setBlob(e.target.value)}
        rows={4}
        style={{ width: "100%" }}
      />
      <div className="row">
        <button className="btn-primary" onClick={activate} disabled={!blob}>
          Activate
        </button>
        <button onClick={checkStatus}>Check status</button>
      </div>
      {status && (
        <div>
          <p className="muted">{status.message}</p>
          {status.info && (
            <p className="muted">
              License: {status.info.license_id} — {status.info.name}
            </p>
          )}
        </div>
      )}
      {error && <p style={{ color: "var(--danger)" }}>{error}</p>}
    </div>
  );
}
