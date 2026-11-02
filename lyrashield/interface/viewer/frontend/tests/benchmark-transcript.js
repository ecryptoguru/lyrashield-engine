// Standalone benchmark: node tests/benchmark-transcript.js [baseline-static-dir]
import { chromium } from "playwright";
import { startPythonServer } from "./python-server-fixture.js";
for (const messages of [10000, 50000]) {
  const args = ["--messages", String(messages)];
  if (process.argv[2]) args.push("--static", process.argv[2]);
  const server = await startPythonServer("tests/viewer_performance_server.py", args, { startupTimeout: 30_000 });
  let browser;
  try {
    const { url, metrics } = server;
    browser = await chromium.launch({ headless: true });
    for (const width of [1440, 375]) {
      const page = await browser.newPage({ viewport: { width, height: 1000 } });
      page.setDefaultTimeout(30000);
      await page.addInitScript(() => localStorage.setItem("strix_viewer_trust_dismissed", "1"));
      await page.goto(url);
      await page.locator(".react-flow__node").first().waitFor();
      const start = performance.now();
      let outcome;
      try {
        await page.locator(".react-flow__node").first().click();
        await page.getByText(new RegExp(`Message ${messages - 1}:`)).waitFor();
        outcome = { open_to_last_message_ms: Math.round(performance.now() - start), rendered_events: await page.locator("dialog .py-1 > div.flex").count(), overflow: await page.evaluate(() => document.documentElement.scrollWidth > innerWidth) };
        if (!process.argv[2]) await page.screenshot({ animations: "disabled", path: `/tmp/task2-window-${messages}-${width}.png` });
      } catch (error) { outcome = { timeout_or_error: error.message.split("\n")[0], elapsed_ms: Math.round(performance.now() - start) }; }
      console.log(JSON.stringify({ variant: process.argv[2] ? "baseline" : "window", messages, width, ...metrics, ...outcome }));
      await page.close();
    }
  } finally { await browser?.close(); await server.stop(); }
}
