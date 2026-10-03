import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

const frontendRoot = fileURLToPath(new URL("..", import.meta.url));

async function withViewerModule(modulePath, callback) {
  const vite = await createServer({
    configFile: path.join(frontendRoot, "vite.config.ts"),
    server: { middlewareMode: true },
    appType: "custom",
    logLevel: "silent",
  });
  try {
    const module = await vite.ssrLoadModule(modulePath);
    await callback(module);
  } finally {
    await vite.close();
  }
}

test("fetchAll preserves report failures for the UI", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const pathname = String(input);
    if (pathname === "/api/run") {
      return new Response(JSON.stringify({ run_id: "run-1", status: "completed", finished: true }));
    }
    if (pathname === "/api/vulnerabilities") return new Response("[]");
    if (pathname === "/api/report") return new Response("{}", { status: 500 });
    if (pathname === "/api/transcript") return new Response("{}");
    throw new Error(`Unexpected viewer request: ${pathname}`);
  };

  try {
    await withViewerModule("/src/data/serverSource.ts", async ({ fetchAll }) => {
      const run = await fetchAll();
      assert.equal(run.reportMarkdown, null);
      assert.equal(run.reportError, "The report could not be loaded.");
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("report load error is announced and offers a retry", async () => {
  await withViewerModule("/src/components/ReportLoadError.tsx", async ({ ReportLoadError }) => {
    const html = renderToStaticMarkup(
      React.createElement(ReportLoadError, {
        message: "The report could not be loaded.",
        onRetry: () => undefined,
      })
    );
    assert.match(html, /role="alert"/);
    assert.match(html, /The report could not be loaded\./);
    assert.match(html, />Retry</);
  });
});
