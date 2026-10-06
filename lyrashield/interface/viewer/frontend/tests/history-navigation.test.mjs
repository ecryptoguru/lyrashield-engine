import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";
import { fileURLToPath } from "node:url";

const entry = {
  name: "Friendly display name", directory_name: "stored-directory", target: null,
  scan_mode: "deep", status: "completed", start_time: null, end_time: null,
  finished: true, severity_counts: { critical: 0, high: 0, medium: 0, low: 0 },
};
const runs = { locked: false, count: 1, runs: [entry] };
const vite = await createServer({
  root: fileURLToPath(new URL("..", import.meta.url)),
  server: { middlewareMode: true, hmr: false },
  optimizeDeps: { noDiscovery: true, include: [] },
  plugins: [{
    name: "expose-private-selector-for-render-test", enforce: "pre",
    transform(code, id) {
      if (id.endsWith("/src/App.tsx")) return code + "\nexport { RunSwitcher };\n";
    },
  }],
});
try {
  const { RunSwitcher } = await vite.ssrLoadModule("/src/App.tsx");
  const { default: PastRunsView } = await vite.ssrLoadModule("/src/components/PastRunsView.tsx");
  test("run selector provides keyboard-native directory selection and current-run fallback", () => {
    const html = renderToStaticMarkup(createElement(RunSwitcher, {
      runs, activeRun: "stored-directory", launchedName: "Launched run", onSelect: () => {},
    }));
    assert.match(html, /<select[^>]+aria-label="Switch pentest"/);
    assert.match(html, /<option value="stored-directory" selected=""/);
    assert.match(html, /<option value="">Current run: Launched run/);
    assert.match(html, /Friendly display name/);
  });
  test("history highlights the selected directory even when its display name differs", () => {
    const html = renderToStaticMarkup(createElement(PastRunsView, {
      runs, activeRun: "stored-directory", onSelectRun: () => {},
    }));
    assert.match(html, /aria-current="true"/);
    assert.match(html, /Friendly display name/);
  });
} finally {
  await vite.close();
}
