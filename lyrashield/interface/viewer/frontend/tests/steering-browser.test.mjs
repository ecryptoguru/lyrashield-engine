import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = fileURLToPath(new URL("../../../../../", import.meta.url));
const python = resolve(root, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");

for (const viewport of [{ width: 1440, height: 1000 }, { width: 375, height: 812 }]) {
  test(`steering acknowledgement, retries, controls and historical binding at ${viewport.width}px`, { timeout: 30_000 }, async () => {
    const server = spawn(python, [resolve(root, "tests/viewer_steering_server.py")], {
      cwd: root, env: { ...process.env, PYTHONPATH: root }, stdio: ["ignore", "pipe", "pipe"],
    });
    let browser;
    try {
      const [ready] = await once(server.stdout, "data");
      const { url } = JSON.parse(ready.toString());
      browser = await chromium.launch({ headless: true });
      const page = await browser.newPage({ viewport });
      page.setDefaultTimeout(8000);
      await page.goto(url);
      await page.getByRole("button", { name: "Dismiss", exact: true }).click();
      await page.getByRole("button", { name: /^Agents/ }).click();
      await page.getByRole("button", { name: "Expand live prompt composer" }).click();
      const input = page.getByRole("textbox", { name: "Steering message" });
      const send = page.getByRole("button", { name: "Send prompt", exact: true });
      const requests = [];
      let mode = "reject";
      await page.route("**/api/agents/steer", async (route) => {
        requests.push(route.request().postDataJSON());
        if (mode === "reject") await route.fulfill({ json: { ok: false, error: "not_delivered" } });
        else if (mode === "unknown") await route.abort("timedout");
        else await route.continue();
      });
      await input.fill("review auth");
      await send.click();
      await page.getByRole("status").filter({ hasText: "Could not reach that agent" }).waitFor();
      assert.equal(await input.inputValue(), "review auth");
      mode = "unknown";
      await send.click();
      await page.getByRole("status").filter({ hasText: "Delivery unknown" }).waitFor();
      assert.equal(await input.inputValue(), "review auth");
      assert.notEqual(requests[0].submission_id, requests[1].submission_id);
      mode = "accept";
      await send.click();
      await page.getByRole("status").filter({ hasText: "Queued for Root agent" }).waitFor();
      assert.equal(await input.inputValue(), "");
      assert.equal(requests[1].submission_id, requests[2].submission_id);
      assert.equal(requests[2].run, "current-directory");
      const resume = page.getByRole("button", { name: "Resume scan", exact: true });
      assert.equal(await resume.isDisabled(), true);
      await page.getByText("Current limit $1.20. Increase adds $1.20 and keeps the scan paused.").waitFor();
      await page.getByRole("button", { name: "Increase budget", exact: true }).click();
      await page.getByText("Current limit $2.40. Increase adds $1.20 and keeps the scan paused.").waitFor();
      assert.equal(await resume.isDisabled(), false);
      const capsUrl = new URL("/api/capabilities", url).href;
      assert.equal((await (await page.request.get(capsUrl)).json()).budget.paused, true);
      await resume.click();
      await page.getByRole("status").filter({ hasText: "Resume accepted." }).waitFor();
      assert.equal((await (await page.request.get(capsUrl)).json()).budget.paused, false);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      await page.getByRole("button", { name: /^Past runs/ }).last().click();
      await page.getByRole("button").filter({ hasText: "past-directory" }).click();
      await page.getByRole("button", { name: /^Agents/ }).click();
      await page.getByRole("heading", { name: "Agent graph", exact: true }).waitFor();
      assert.equal(await page.getByRole("button", { name: "Expand live prompt composer" }).count(), 0);
      const response = await page.request.post(new URL("/api/agents/steer", url).href, {
        data: { run: "past-directory", agent_id: "root", message: "cross-run", submission_id: "cross-run" },
      });
      assert.equal(response.status(), 409);
    } finally {
      await browser?.close();
      if (server.exitCode === null) {
        server.kill("SIGTERM");
        await once(server, "exit");
      }
    }
  });
}
