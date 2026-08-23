// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type ByokConfig = {
  provider: string;
  azureEndpoint: string;
  azureDeployment: string;
};

export default function ByokSetup() {
  const [config, setConfig] = useState<ByokConfig>({
    provider: "chatgpt",
    azureEndpoint: "",
    azureDeployment: "",
  });
  const [azureKey, setAzureKey] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  const save = async () => {
    setError("");
    setStatus("");
    try {
      await invoke("byok_save", {
        config,
        azureKey: azureKey || null,
      });
      setStatus(
        "BYOK setup saved. The API key lives in the OS keychain; only the selected " +
          "provider's environment reaches a scan."
      );
    } catch (e) {
      setError(`${e}`);
    }
  };

  return (
    <div className="panel">
      <h2>Connect AI (BYOK)</h2>
      <p className="muted">
        Bring your own keys. Credentials are stored in the OS keychain — never in
        plaintext files, never on the command line, and never sent to a provider you
        did not select.
      </p>

      <div className="row">
        <select
          value={config.provider}
          onChange={(e) => setConfig({ ...config, provider: e.target.value })}
        >
          <option value="chatgpt">ChatGPT subscription (OAuth)</option>
          <option value="azure">Azure OpenAI</option>
        </select>
      </div>

      {config.provider === "chatgpt" && (
        <p className="muted">
          Sign in with your ChatGPT subscription by running
          <code> lyrashield auth login chatgpt</code> in a terminal once. The desktop
          app validates that auth state when you save.
        </p>
      )}

      {config.provider === "azure" && (
        <>
          <input
            placeholder="Azure OpenAI API key"
            type="password"
            value={azureKey}
            onChange={(e) => setAzureKey(e.target.value)}
            style={{ width: "100%" }}
          />
          <input
            placeholder="Endpoint (https://xxx.openai.azure.com)"
            value={config.azureEndpoint}
            onChange={(e) => setConfig({ ...config, azureEndpoint: e.target.value })}
            style={{ width: "100%", marginTop: 8 }}
          />
          <input
            placeholder="Deployment name"
            value={config.azureDeployment}
            onChange={(e) => setConfig({ ...config, azureDeployment: e.target.value })}
            style={{ width: "100%", marginTop: 8 }}
          />
        </>
      )}

      <p className="experimental">Local / self-hosted models: experimental / coming</p>

      <div className="row">
        <button className="btn-primary" onClick={save}>Save setup</button>
      </div>
      {status && <p className="muted">{status}</p>}
      {error && <p style={{ color: "var(--danger)" }}>{error}</p>}
    </div>
  );
}
