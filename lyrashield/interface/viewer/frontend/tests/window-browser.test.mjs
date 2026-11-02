import test from "node:test";
import assert from "node:assert/strict";
import { chromium } from "playwright";
import { startPythonServer } from "./python-server-fixture.js";
for (const width of [1440, 375]) test(`bounded transcript older paging and retry at ${width}px`, { timeout: 30000 }, async () => {
  const server = await startPythonServer("tests/viewer_performance_server.py", ["--messages", "350"]);
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width, height: 1000 } }); page.setDefaultTimeout(5000);
    await page.goto(server.url); await page.locator(".react-flow__node").first().click();
    await page.getByText(/^Message 349:/).waitFor();
    assert.equal(await page.locator("dialog .py-1 > div.flex").count(), 100);
    assert.equal(await page.getByText(/^Message 0:/).count(), 0);
    let fail = true;
    await page.route("**/api/transcript*", async route => {
      if (new URL(route.request().url()).searchParams.has("before") && fail) await route.fulfill({ status: 500, json: {} });
      else await route.continue();
    });
    await page.getByRole("button", { name: "Load older activity", exact: true }).click();
    await page.getByRole("alert").filter({ hasText: "Older activity could not be loaded" }).waitFor();
    assert.equal(await page.getByText(/^Message 349:/).isVisible(), true);
    fail = false;
    await page.getByRole("button", { name: "Retry older activity", exact: true }).click();
    await page.getByText(/^Message 249:/).waitFor();
    assert.equal(await page.getByText(/^Message 349:/).count(), 0);
    await page.getByRole("button", { name: "Load older activity", exact: true }).click();
    await page.getByText(/^Message 149:/).waitFor();
    await page.getByRole("button", { name: "Load older activity", exact: true }).click();
    await page.getByText(/^Message 0:/).waitFor();
    assert.equal(await page.locator("dialog .py-1 > div.flex").count(), 50);
    assert.equal(await page.getByRole("button", { name: "Load older activity", exact: true }).count(), 0);
    await page.getByRole("button", { name: "Return to latest activity", exact: true }).click();
    await page.getByText(/^Message 349:/).waitFor();
    assert.equal(await page.locator("dialog .py-1 > div.flex").count(), 100);
    await page.keyboard.press("Escape");
    await page.getByRole("dialog").waitFor({ state: "hidden" });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  } finally { await browser?.close(); await server.stop(); }
});
