import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

const frontendRoot = fileURLToPath(new URL("..", import.meta.url));

async function renderRunDetails(raw) {
  const server = await createServer({
    configFile: path.join(frontendRoot, "vite.config.ts"),
    server: { middlewareMode: true },
    appType: "custom",
    logLevel: "silent",
  });

  try {
    const { RunDetails } = await server.ssrLoadModule("/src/components/RunDetails.tsx");
    return renderToStaticMarkup(
      React.createElement(RunDetails, { raw, durationSeconds: 1 })
    );
  } finally {
    await server.close();
  }
}

test("run details shows metered fallback cost for a subscription-routed run", async () => {
  const html = await renderRunDetails({
    auth_mode: "subscription",
    llm_usage: {
      cost: 0.0002,
      agents: [{ agent_id: "root", model: "openai/gpt-6-luna" }],
      request_usage_entries: [{ model: "openai/gpt-6-luna" }],
    },
  });

  assert.match(html, /ChatGPT subscription route \(model not reported\), openai\/gpt-6-luna/);
  assert.match(html, /\$0\.0002/);
  assert.match(html, /subscription \+ metered/);
  assert.doesNotMatch(html, /\$0\.00\s*\(subscription\)/);
});

test("run details preserves ledger precision for very small metered costs", async () => {
  const html = await renderRunDetails({
    auth_mode: "subscription",
    llm_usage: {
      cost: 0.00002,
      agents: [{ agent_id: "root", model: "openai/gpt-6-luna" }],
      request_usage_entries: [{ model: "openai/gpt-6-luna" }],
    },
  });

  assert.match(html, /\$0\.00002/);
  assert.match(html, /ChatGPT subscription route \(model not reported\), openai\/gpt-6-luna/);
  assert.match(html, /subscription \+ metered/);
});

test("run details displays the smallest nonzero ledger cost", async () => {
  const html = await renderRunDetails({
    auth_mode: "subscription",
    llm_usage: {
      cost: 0.0000000001,
      agents: [{ agent_id: "root", model: "openai/gpt-6-luna" }],
    },
  });

  assert.match(html, /\$0\.0000000001/);
});

test("run details keeps zero-cost subscription runs labeled as subscription", async () => {
  const html = await renderRunDetails({
    auth_mode: "subscription",
    llm_usage: {
      cost: 0,
      agents: [{ agent_id: "root", model: "chatgpt/gpt-6-luna" }],
    },
  });

  assert.match(html, /\$0\.00/);
  assert.match(html, /\(subscription\)/);
  assert.doesNotMatch(html, /subscription \+ metered/);
});
