import test from "node:test";
import { chromium } from "playwright";
import assert from "node:assert/strict";
import { startPythonServer } from "./python-server-fixture.js";

test("mobile history opens empty live runs and preserves already-selected run data", { timeout: 30_000 }, async () => {
  const server = await startPythonServer("tests/viewer_navigation_server.py");
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 375, height: 812 } });
    page.setDefaultTimeout(8000);
    // Live resources poll every 500ms; wait for rendered run identity instead
    // of requiring a 500ms network-idle gap between those requests.
    await page.goto(server.url, { waitUntil: "domcontentloaded" });
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
    await server.stop();
  }
});
