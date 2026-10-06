import test from "node:test";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import assert from "node:assert/strict";

const root = fileURLToPath(new URL("../../../../../", import.meta.url));
const python = resolve(root, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");

test("mobile history opens empty live runs and preserves already-selected run data", { timeout: 30_000 }, async () => {
  const server = spawn(python, [resolve(root, "tests/viewer_navigation_server.py")], {
    cwd: root, stdio: ["ignore", "pipe", "pipe"],
  });
  const ready = once(server.stdout, "data");
  let browser;
  try {
    const [data] = await ready;
    const { url } = JSON.parse(data.toString());
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 375, height: 812 } });
    await page.goto(url);
    await page.waitForLoadState("networkidle");
    const current = page.getByRole("heading", { name: "Current friendly name", exact: true });
    const history = page.getByRole("button", { name: "Past runs", exact: true }).last();
    await current.waitFor();
    await history.click();
    await page.getByRole("button", { name: "Back to current run" }).click();
    await page.getByRole("button", { name: "Pentest Overview", exact: true }).waitFor();
    assert.equal(await current.isVisible(), true);
    assert.equal(await page.getByRole("heading", { name: "Past runs", exact: true }).count(), 0);

    await history.click();
    await page.getByRole("button").filter({ hasText: "Past friendly name" }).click();
    const past = page.getByRole("heading", { name: "Past friendly name", exact: true });
    await past.waitFor();
    await page.getByRole("button", { name: "Pentest Overview", exact: true }).waitFor();
    assert.equal(await page.getByRole("heading", { name: "Past runs", exact: true }).count(), 0);

    await history.click();
    await page.getByRole("button").filter({ hasText: "Past friendly name" }).click();
    await page.getByRole("button", { name: "Pentest Overview", exact: true }).waitFor();
    assert.equal(await past.isVisible(), true);
  } finally {
    await browser?.close();
    if (server.exitCode === null) {
      server.kill("SIGTERM");
      await once(server, "exit");
    }
  }
});
