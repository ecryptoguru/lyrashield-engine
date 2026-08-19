// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type SyncState = {
  connected: boolean;
  api_key_set: boolean;
  last_synced_at: number | null;
  entitlement_ok: boolean;
};

export default function Settings() {
  const [profiles, setProfiles] = useState<Record<string, string>>({
    SAFE: "fallback",
    QUICK: "fallback",
    STANDARD: "terra",
    DEEP: "luna",
    CUSTOM: "luna",
  });
  const [syncApiKey, setSyncApiKey] = useState("");
  const [syncState, setSyncState] = useState<SyncState | null>(null);

  const profileOptions = ["luna", "terra", "fallback"];

  const connectSync = async () => {
    try {
      const s = await invoke<SyncState>("sync_connect", { apiKey: syncApiKey });
      setSyncState(s);
    } catch (e) {
      setSyncState({ connected: false, api_key_set: false, last_synced_at: null, entitlement_ok: false });
      alert(`${e}`);
    }
  };

  const checkSync = async () => {
    const s = await invoke<SyncState>("sync_status");
    setSyncState(s);
  };

  return (
    <div className="panel">
      <h2>Settings</h2>

      <h3>Model profile per scan mode</h3>
      <p className="muted">Choose LUNA / TERRA / fallback for each scan mode.</p>
      {Object.entries(profiles).map(([mode, profile]) => (
        <div className="row" key={mode}>
          <span style={{ width: 100 }}>{mode}</span>
          <select
            value={profile}
            onChange={(e) => setProfiles({ ...profiles, [mode]: e.target.value })}
          >
            {profileOptions.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </div>
      ))}

      <h3>Cloud sync (opt-in)</h3>
      <p className="muted">
        Nothing syncs by default. Connect your LyraShield account to sync chosen findings/reports.
        Entitlement is enforced server-side.
      </p>
      <input
        placeholder="LYRASHIELD_API_KEY"
        value={syncApiKey}
        onChange={(e) => setSyncApiKey(e.target.value)}
        style={{ width: "100%" }}
      />
      <div className="row">
        <button className="btn-primary" onClick={connectSync} disabled={!syncApiKey}>
          Connect
        </button>
        <button onClick={checkSync}>Check status</button>
      </div>
      {syncState && (
        <p className="muted">
          {syncState.connected
            ? "Sync connected. Entitlement OK."
            : "Sync not connected."}
        </p>
      )}
    </div>
  );
}
