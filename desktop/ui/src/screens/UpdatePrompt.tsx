// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

// The webview never verifies signatures itself (C5): `signature_valid` is
// gone. An update is only reported after the Tauri updater plugin has
// cryptographically accepted the manifest, and installation goes through the
// native command that re-checks eligibility and delegates to the plugin.
type UpdateInfo = {
  available: boolean;
  version: string;
  notes: string;
};

export default function UpdatePrompt() {
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [installing, setInstalling] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const check = async () => {
    setError("");
    setMessage("");
    try {
      const i = await invoke<UpdateInfo>("updater_check");
      setInfo(i);
    } catch (e) {
      setError(`${e}`);
    }
  };

  const install = async () => {
    setError("");
    setMessage("");
    setInstalling(true);
    try {
      await invoke("updater_install");
      setMessage("Verified update installed — restart to finish.");
    } catch (e) {
      setError(`${e}`);
    } finally {
      setInstalling(false);
    }
  };

  return (
    <div className="panel">
      <h2>Updates</h2>
      <p className="muted">
        Updates are signed (ed25519) and verified by the updater's native
        cryptographic check before anything is applied. No remote-code eval.
        Artifacts are hosted on GitHub Releases. After your update window
        expires, the app keeps running (perpetual fallback) but won't apply
        newer builds.
      </p>
      <button className="btn-primary" onClick={check}>Check for updates</button>
      {info && (
        <div>
          {info.available ? (
            <>
              <p>Version {info.version} is available (signature verified by the updater).</p>
              <p className="muted">{info.notes}</p>
              <button onClick={install} disabled={installing}>
                {installing ? "Installing…" : "Download and install verified update"}
              </button>
            </>
          ) : (
            <p className="muted">{info.notes}</p>
          )}
        </div>
      )}
      {message && <p className="muted">{message}</p>}
      {error && <p style={{ color: "var(--danger)" }}>{error}</p>}
    </div>
  );
}
