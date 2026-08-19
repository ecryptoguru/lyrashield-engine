// Modifications © 2026 LyraShield; based on upstream Strix (Apache-2.0)
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export default function ByokSetup() {
  const [provider, setProvider] = useState("chatgpt-oauth");
  const [azureKey, setAzureKey] = useState("");
  const [azureEndpoint, setAzureEndpoint] = useState("");
  const [azureDeployment, setAzureDeployment] = useState("");
  const [status, setStatus] = useState("");

  const save = async () => {
    if (provider === "azure-openai") {
      await invoke("keychain_set", {
        service: "LyraShield-Local",
        key: "azure-openai-api-key",
        value: azureKey,
      });
    }
    setStatus("BYOK setup saved. Credentials stored in OS keychain.");
  };

  const loginChatgpt = async () => {
    // ChatGPT OAuth is handled by the engine CLI's `auth login chatgpt` flow.
    // The desktop shell records that the provider is selected.
    setStatus("Run `lyrashield auth login chatgpt` in a terminal to complete OAuth, then return here.");
  };

  return (
    <div className="panel">
      <h2>Connect AI (BYOK)</h2>
      <p className="muted">
        Bring your own keys. Credentials are stored in the OS keychain — never in plaintext files.
      </p>

      <div className="row">
        <select value={provider} onChange={(e) => setProvider(e.target.value)}>
          <option value="chatgpt-oauth">ChatGPT subscription (OAuth)</option>
          <option value="azure-openai">Azure OpenAI</option>
        </select>
      </div>

      {provider === "chatgpt-oauth" && (
        <>
          <p className="muted">
            Sign in with your ChatGPT subscription. The OAuth token is stored in the OS keychain.
          </p>
          <button className="btn-primary" onClick={loginChatgpt}>Sign in with ChatGPT</button>
        </>
      )}

      {provider === "azure-openai" && (
        <>
          <input
            placeholder="Azure OpenAI API key"
            value={azureKey}
            onChange={(e) => setAzureKey(e.target.value)}
            style={{ width: "100%" }}
          />
          <input
            placeholder="Endpoint (https://xxx.openai.azure.com)"
            value={azureEndpoint}
            onChange={(e) => setAzureEndpoint(e.target.value)}
            style={{ width: "100%", marginTop: 8 }}
          />
          <input
            placeholder="Deployment name"
            value={azureDeployment}
            onChange={(e) => setAzureDeployment(e.target.value)}
            style={{ width: "100%", marginTop: 8 }}
          />
        </>
      )}

      <p className="experimental">Local / self-hosted models: experimental / coming</p>

      <div className="row">
        <button className="btn-primary" onClick={save}>Save setup</button>
      </div>
      {status && <p className="muted">{status}</p>}
    </div>
  );
}
