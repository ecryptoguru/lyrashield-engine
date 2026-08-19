// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type UpdateInfo = {
  available: boolean;
  version: string;
  notes: string;
  signature_valid: boolean;
};

export default function UpdatePrompt() {
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [error, setError] = useState("");

  const check = async () => {
    setError("");
    try {
      const i = await invoke<UpdateInfo>("updater_check");
      setInfo(i);
    } catch (e) {
      setError(`${e}`);
    }
  };

  return (
    <div className="panel">
      <h2>Updates</h2>
      <p className="muted">
        Updates are signed (ed25519) and verified before applying. No remote-code eval.
        Artifacts are hosted on GitHub Releases. After your update window expires, the app
        keeps running (perpetual fallback) but won't apply newer builds.
      </p>
      <button className="btn-primary" onClick={check}>Check for updates</button>
      {info && (
        <div>
          {info.available ? (
            <>
              <p>Version {info.version} is available.</p>
              <p className="muted">{info.notes}</p>
              <p className="muted">
                Signature: {info.signature_valid ? "valid" : "missing"}
              </p>
            </>
          ) : (
            <p className="muted">{info.notes}</p>
          )}
        </div>
      )}
      {error && <p style={{ color: "var(--danger)" }}>{error}</p>}
    </div>
  );
}
