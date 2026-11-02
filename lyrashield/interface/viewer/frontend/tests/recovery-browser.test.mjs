import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
const root = fileURLToPath(new URL("../../../../../", import.meta.url));
async function fixture(fn, viewport = { width: 1440, height: 1000 }) {
  const server = spawn(resolve(root, ".venv/bin/python"), [resolve(root, "tests/viewer_steering_server.py")], { cwd: root, env: { ...process.env, PYTHONPATH: root }, stdio: ["ignore", "pipe", "pipe"] });
  let browser;
  try {
    const [ready] = await once(server.stdout, "data");
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport }); page.setDefaultTimeout(8000);
    await fn(page, JSON.parse(ready.toString()).url);
  } finally {
    for (const context of browser?.contexts() ?? []) for (const page of context.pages()) await page.unrouteAll({ behavior: "ignoreErrors" });
    await browser?.close(); server.kill("SIGTERM"); await once(server, "exit");
  }
}
test("terminal transcript failure and history failure remain visible and independently retryable", { timeout: 20000 }, async () => fixture(async (page, url) => {
  let transcriptFailed = true, historyFailed = true;
  await page.route("**/api/run*", async route => { const response = await route.fetch({ maxRetries: 2 }); await route.fulfill({ json: { ...await response.json(), finished: true, status: "completed" } }); });
  await page.route("**/api/transcript*", route => transcriptFailed ? route.fulfill({ status: 500, json: {} }) : route.continue());
  await page.route("**/api/runs", route => historyFailed ? route.fulfill({ status: 500, json: {} }) : route.continue());
  await page.goto(url);
  await page.getByRole("alert").filter({ hasText: "Transcript could not be loaded" }).waitFor();
  transcriptFailed = false;
  await page.getByRole("button", { name: "Retry transcript", exact: true }).click();
  await page.getByRole("button", { name: /^Agents/ }).click();
  await page.getByRole("heading", { name: "Agent graph" }).waitFor();
  await page.getByRole("button", { name: /^Past runs/ }).click();
  await page.getByRole("alert").filter({ hasText: "History could not be loaded" }).waitFor();
  historyFailed = false;
  await page.getByRole("button", { name: "Retry history", exact: true }).click();
  await page.getByRole("button").filter({ hasText: "past-directory" }).waitFor();
}));
test("native keyboard targets, IME composition and sidebar restore", { timeout: 20000 }, async () => fixture(async (page, url) => {
  await page.addInitScript(() => localStorage.setItem("strix_viewer_sidebar_collapsed", "1"));
  await page.route("**/api/transcript*", async route => { const response = await route.fetch({ maxRetries: 2 }); const json = await response.json(); json.agents.push({ ...json.agents[0], id: "child", parent_id: "root", name: "Child agent", status: "running" }); await route.fulfill({ json }); });
  await page.goto(url);
  await page.getByRole("button", { name: "Expand sidebar", exact: true }).focus(); await page.keyboard.press("Enter");
  await page.getByRole("button", { name: /^Agents/ }).click();
  await page.getByRole("button", { name: "Expand live prompt composer" }).click();
  const target = page.getByRole("combobox", { name: "Steering target" });
  await page.waitForFunction(() => document.activeElement?.getAttribute("aria-label") === "Steering message");
  await target.focus(); await page.keyboard.press("c"); await page.keyboard.press("Enter");
  assert.equal(await target.inputValue(), "child");
  const input = page.getByRole("textbox", { name: "Steering message" }); await input.fill("日本語");
  let sent = 0; await page.route("**/api/agents/steer", route => { sent++; return route.continue(); });
  await input.dispatchEvent("keydown", { key: "Enter", isComposing: true, keyCode: 229 });
  assert.equal(sent, 0); assert.equal(await input.inputValue(), "日本語");
  await input.press("Enter"); await page.getByRole("status").filter({ hasText: "Queued for Child agent" }).waitFor();
}));
test("mobile privacy notice leaves composer pointer target accessible", { timeout: 15000 }, async () => fixture(async (page, url) => {
  await page.goto(url); await page.getByRole("button", { name: /^Agents/ }).click();
  await page.getByRole("button", { name: "Expand live prompt composer" }).click();
  await page.getByRole("textbox", { name: "Steering message" }).fill("reachable");
  await page.getByRole("button", { name: "Send prompt", exact: true }).click();
  await page.getByRole("status").filter({ hasText: "Queued for Root agent" }).waitFor();
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
}, { width: 375, height: 812 }));
test("unknown child retry keeps original identity after that child disappears", { timeout: 20000 }, async () => fixture(async (page, url) => {
  let childVisible = true;
  await page.route("**/api/transcript*", async route => { const response = await route.fetch({ maxRetries: 2 }); const json = await response.json(); if (childVisible) json.agents.push({ ...json.agents[0], id: "child", parent_id: "root", name: "Child agent", status: "running" }); await route.fulfill({ json }); });
  await page.goto(url); await page.getByRole("button", { name: /^Agents/ }).click();
  await page.getByRole("button", { name: "Expand live prompt composer" }).click();
  const target = page.getByRole("combobox", { name: "Steering target" }); await target.selectOption("child");
  const requests = []; let unknown = true;
  await page.route("**/api/agents/steer", route => { requests.push(route.request().postDataJSON()); return unknown ? route.abort("timedout") : route.fulfill({ json: { ok: true } }); });
  await page.getByRole("textbox", { name: "Steering message" }).fill("original instruction");
  await page.getByRole("button", { name: "Send prompt", exact: true }).click();
  await page.getByRole("status").filter({ hasText: "Delivery unknown" }).waitFor();
  childVisible = false;
  await page.getByRole("option", { name: "Original target (child)" }).waitFor({ state: "attached" });
  assert.equal(await target.isDisabled(), true);
  unknown = false; await page.getByRole("button", { name: "Send prompt", exact: true }).click();
  await page.getByRole("status").filter({ hasText: "Queued" }).waitFor();
  assert.equal(requests.length, 2);
  assert.deepEqual(requests[0], requests[1]);
  assert.equal(requests[1].agent_id, "child");
}));
test("subcent budget display refreshes after another client increases the limit", { timeout: 20000 }, async () => fixture(async (page, url) => {
  let increased = false;
  await page.route("**/api/capabilities", async route => { const response = await route.fetch({ maxRetries: 2 }); const json = await response.json(); json.budget = { ...json.budget, increment_usd: 0.004, limit_usd: increased ? 0.008 : 0.004, resume_requires_increase: !increased }; await route.fulfill({ json }); });
  await page.goto(url); await page.getByRole("button", { name: /^Agents/ }).click();
  await page.getByRole("button", { name: "Expand live prompt composer" }).click();
  await page.getByText("Current limit $0.004. Increase adds $0.004 and keeps the scan paused.").waitFor();
  const resume = page.getByRole("button", { name: "Resume scan", exact: true }); assert.equal(await resume.isDisabled(), true);
  increased = true;
  await page.getByText("Current limit $0.008. Increase adds $0.004 and keeps the scan paused.").waitFor();
  assert.equal(await resume.isDisabled(), false);
}));
test("run switch aborts stale requests and keeps launched label stable", { timeout: 20000 }, async () => fixture(async (page, url) => {
  let release;
  const held = new Promise(resolve => { release = resolve; });
  let requested;
  const started = new Promise(resolve => { requested = resolve; });
  const cancelled = [];
  page.on("requestfailed", request => cancelled.push(request.url()));
  await page.route("**/api/transcript*", async route => {
    if (new URL(route.request().url()).searchParams.get("run") === "past-directory") {
      requested(); await held; await route.fulfill({ json: { agents: [{ id: "stale", name: "Stale historical agent", status: "running", parent_id: null }], events: [] } }).catch(() => {});
    } else await route.continue();
  });
  await page.goto(url);
  const switcher = page.getByRole("combobox", { name: "Switch pentest" }); await switcher.waitFor();
  const launchedLabel = await switcher.locator("option").first().textContent();
  await switcher.selectOption("past-directory"); await started;
  await page.getByRole("heading", { name: "past-directory", exact: true }).waitFor();
  assert.equal(await switcher.locator("option").first().textContent(), launchedLabel);
  await switcher.selectOption("");
  await page.getByRole("heading", { name: "current-directory", exact: true }).waitFor();
  release();
  await page.waitForFunction(() => !document.body.textContent.includes("past-directory") || document.querySelector('select[aria-label="Switch pentest"]').value === "");
  assert.equal(await page.getByText("Stale historical agent", { exact: true }).count(), 0);
  assert.ok(cancelled.some(path => path.includes("run=past-directory")), "switch aborts the old fetch");
}));
test("hung terminal transcript has a finite deadline and can be retried", { timeout: 25000 }, async () => fixture(async (page, url) => {
  let hanging = true; const held = [];
  await page.route("**/api/run*", async route => { const response = await route.fetch({ maxRetries: 2 }); await route.fulfill({ json: { ...await response.json(), finished: true, status: "completed" } }); });
  await page.route("**/api/transcript*", route => { if (hanging) held.push(route); else return route.continue(); });
  await page.goto(url);
  await page.getByRole("alert").filter({ hasText: "Transcript could not be loaded" }).waitFor({ timeout: 12000 });
  await page.getByText("Download the report for this run", { exact: true }).waitFor();
  hanging = false;
  await page.getByRole("button", { name: "Retry transcript", exact: true }).click();
  await page.getByRole("button", { name: /^Agents/ }).click(); await page.getByRole("heading", { name: "Agent graph" }).waitFor();
  for (const route of held) await route.abort().catch(() => {});
}));
test("terminal findings and report retry separately without blocking agent data", { timeout: 20000 }, async () => fixture(async (page, url) => {
  let findingsFailed = true, reportFailed = true;
  await page.route("**/api/run*", async route => { const response = await route.fetch({ maxRetries: 2 }); await route.fulfill({ json: { ...await response.json(), finished: true, status: "completed" } }); });
  await page.route("**/api/vulnerabilities*", route => findingsFailed ? route.fulfill({ status: 500, json: {} }) : route.continue());
  await page.route("**/api/report*", route => reportFailed ? route.fulfill({ status: 500, json: {} }) : route.continue());
  await page.goto(url);
  await page.getByRole("alert").filter({ hasText: "Findings could not be loaded" }).waitFor();
  const reportAlert = page.getByRole("alert").filter({ hasText: "The report could not be loaded" }); await reportAlert.waitFor();
  findingsFailed = false; await page.getByRole("button", { name: "Retry findings", exact: true }).click();
  await page.getByRole("alert").filter({ hasText: "Findings could not be loaded" }).waitFor({ state: "hidden" });
  assert.equal(await reportAlert.isVisible(), true);
  reportFailed = false; await reportAlert.getByRole("button", { name: "Retry", exact: true }).click();
  await reportAlert.waitFor({ state: "hidden" });
  await page.getByRole("button", { name: /^Agents/ }).click(); await page.getByRole("heading", { name: "Agent graph" }).waitFor();
}));

test("transient capability failure can recover steering without reloading", { timeout: 20000 }, async () => fixture(async (page, url) => {
  let failed = true;
  await page.route("**/api/capabilities", route => failed ? route.fulfill({ status: 500, json: {} }) : route.continue());
  await page.goto(url);
  await page.getByRole("alert").filter({ hasText: "Live controls could not be loaded" }).waitFor();
  assert.equal(await page.getByRole("button", { name: "Expand live prompt composer" }).count(), 0);
  failed = false; await page.getByRole("button", { name: "Retry live controls", exact: true }).click();
  await page.getByRole("button", { name: /^Agents/ }).click();
  await page.getByRole("button", { name: "Expand live prompt composer" }).waitFor();
}));
test("first mobile history failure has reachable recovery without a successful history response", { timeout: 20000 }, async () => fixture(async (page, url) => {
  let failed = true;
  await page.route("**/api/runs", route => failed ? route.fulfill({ status: 500, json: {} }) : route.continue());
  await page.goto(url);
  await page.getByRole("button", { name: "Retry history", exact: true }).waitFor();
  assert.equal(await page.getByRole("combobox", { name: "Switch pentest" }).count(), 0);
  failed = false;
  await page.getByRole("button", { name: "Retry history", exact: true }).click();
  await page.getByRole("button", { name: /^Past runs/ }).last().click();
  await page.getByRole("button").filter({ hasText: "past-directory" }).waitFor();
}, { width: 375, height: 812 }));
for (const kind of ["message", "increase budget"]) for (const inFlight of [false, true]) {
  test(`${kind} receipt survives completion${inFlight ? " during acknowledgement" : " after unknown acknowledgement"}`, { timeout: 20000 }, async () => fixture(async (page, url) => {
    let finished = false;
    await page.route("**/api/run?*", async route => { const response = await route.fetch({ maxRetries: 2 }); await route.fulfill({ json: { ...await response.json(), finished, ...(finished ? { status: "completed" } : {}) } }); });
    await page.route("**/api/run", async route => { const response = await route.fetch({ maxRetries: 2 }); await route.fulfill({ json: { ...await response.json(), finished, ...(finished ? { status: "completed" } : {}) } }); });
    let release;
    const held = new Promise(resolve => { release = resolve; });
    const requests = [];
    await page.route("**/api/receipts/check", async route => { requests.push(route.request().postDataJSON()); await route.continue(); });
    await page.route(kind === "message" ? "**/api/agents/steer" : "**/api/scan/control", async route => {
      requests.push(route.request().postDataJSON());
      if (requests.length === 1) {
        const accepted = await route.fetch({ maxRetries: 2 });
        assert.equal((await accepted.json()).ok, true);
        if (inFlight) await held;
        await route.fulfill({ json: { ok: false, error: "delivery_unknown" } });
      } else await route.fulfill({ json: { ok: true, status: "queued" } });
    });
    await page.goto(url); await page.getByRole("button", { name: /^Agents/ }).click();
    await page.getByRole("button", { name: "Expand live prompt composer" }).click();
    if (kind === "message") { await page.getByRole("textbox", { name: "Steering message" }).fill("keep exact instruction"); await page.getByRole("button", { name: "Send prompt", exact: true }).click(); }
    else await page.getByRole("button", { name: "Increase budget", exact: true }).click();
    if (!inFlight) await page.getByRole("status").filter({ hasText: "Delivery unknown" }).waitFor();
    finished = true;
    await page.getByRole("button", { name: "Collapse live prompt composer" }).waitFor({ state: "hidden" });
    if (inFlight) release();
    const receipts = page.getByRole("region", { name: "Operator delivery receipts", exact: true });
    await receipts.getByText("Delivery unknown", { exact: false }).waitFor();
    assert.equal(await page.getByRole("button", { name: "Send prompt", exact: true }).count(), 0);
    assert.equal(await page.getByRole("button", { name: "Increase budget", exact: true }).count(), 0);
    await receipts.getByRole("button", { name: `Check ${kind} receipt`, exact: true }).click();
    await receipts.getByText("Acceptance confirmed", { exact: false }).waitFor();
    assert.equal(requests.length, 2);
    assert.deepEqual(requests[0], requests[1]);
    assert.equal(requests[1].run, "current-directory");
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  }, { width: 375, height: 812 }));
}

test("modal message receipt survives completion and dialog teardown", { timeout: 20000 }, async () => fixture(async (page, url) => {
  let finished = false;
  await page.route("**/api/run", async route => { const response = await route.fetch({ maxRetries: 2 }); await route.fulfill({ json: { ...await response.json(), finished, ...(finished ? { status: "completed" } : {}) } }); });
  const submissions = [];
  await page.route("**/api/agents/steer", async route => { submissions.push(route.request().postDataJSON()); await route.fetch({ maxRetries: 2 }); await route.fulfill({ json: { ok: false, error: "delivery_unknown" } }); });
  await page.route("**/api/receipts/check", async route => { submissions.push(route.request().postDataJSON()); await route.continue(); });
  await page.goto(url); await page.getByRole("button", { name: /^Agents/ }).click();
  await page.locator(".react-flow__node").first().click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: "Expand live prompt composer" }).click();
  await dialog.getByRole("textbox", { name: "Steering message" }).fill("original modal message");
  await dialog.getByRole("button", { name: "Send prompt", exact: true }).click();
  await dialog.getByRole("status").filter({ hasText: "Delivery unknown" }).waitFor();
  finished = true;
  await dialog.getByRole("button", { name: "Send prompt", exact: true }).waitFor({ state: "hidden" });
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  const receipts = page.getByRole("region", { name: "Operator delivery receipts", exact: true });
  await receipts.getByRole("button", { name: "Check message receipt", exact: true }).click();
  await receipts.getByText("Acceptance confirmed", { exact: false }).waitFor();
  assert.equal(submissions.length, 2); assert.deepEqual(submissions[0], submissions[1]);
}));
test("lost Resume rejection resolves from a cached receipt after completion without another mutation", { timeout: 20000 }, async () => fixture(async (page, url) => {
  let finished = false;
  await page.route("**/api/run", async route => { const response = await route.fetch({ maxRetries: 2 }); await route.fulfill({ json: { ...await response.json(), finished, ...(finished ? { status: "completed" } : {}) } }); });
  await page.route("**/api/capabilities", async route => { const response = await route.fetch({ maxRetries: 2 }); const json = await response.json(); json.budget.resume_requires_increase = false; await route.fulfill({ json }); });
  const mutations = [], checks = [];
  await page.route("**/api/scan/control", async route => {
    mutations.push(route.request().postDataJSON());
    const response = await route.fetch({ maxRetries: 2 });
    assert.deepEqual(await response.json(), { ok: false, error: "budget_increase_required" });
    await route.fulfill({ json: { ok: false, error: "delivery_unknown" } });
  });
  await page.route("**/api/receipts/check", async route => {
    checks.push(route.request().postDataJSON());
    if (checks.length === 1) await route.fulfill({ status: 403, json: { ok: false, error: "forbidden", status: "rejected" } });
    else await route.continue();
  });
  await page.goto(url); await page.getByRole("button", { name: /^Agents/ }).click();
  await page.getByRole("button", { name: "Expand live prompt composer" }).click();
  await page.getByRole("textbox", { name: "Steering message" }).fill("preserved draft");
  await page.getByRole("button", { name: "Resume scan", exact: true }).click();
  await page.getByRole("status").filter({ hasText: "Delivery unknown" }).waitFor();
  assert.equal(await page.getByRole("textbox", { name: "Steering message" }).inputValue(), "preserved draft");
  finished = true;
  await page.getByRole("button", { name: "Collapse live prompt composer" }).waitFor({ state: "hidden" });
  const receipts = page.getByRole("region", { name: "Operator delivery receipts", exact: true });
  await receipts.getByRole("button", { name: "Check resume receipt", exact: true }).click();
  await receipts.getByRole("button", { name: "Check resume receipt", exact: true }).waitFor();
  assert.equal(await receipts.getByText("Delivery unknown", { exact: false }).count(), 1);
  await receipts.getByRole("button", { name: "Check resume receipt", exact: true }).click();
  await receipts.getByText("not accepted", { exact: false }).waitFor();
  assert.equal(await receipts.getByText("Delivery unknown", { exact: false }).count(), 0);
  assert.equal(mutations.length, 1); assert.equal(checks.length, 2); assert.deepEqual(mutations[0], checks[0]); assert.deepEqual(checks[0], checks[1]);
}));

for (const viewport of [{ width: 1440, height: 1000 }, { width: 375, height: 812 }]) {
  for (const result of ["markdown", "empty", "missing", "failure"]) {
    test(`first report ${result} preserves truthful loading and recovery at ${viewport.width}px`, { timeout: 20000 }, async () => fixture(async (page, url) => {
      let release;
      const held = new Promise(resolve => { release = resolve; });
      let failed = result === "failure";
      await page.route("**/api/run", async route => { const response = await route.fetch(); await route.fulfill({ json: { ...await response.json(), finished: true, status: "completed" } }); });
      await page.route("**/api/report*", async route => {
        await held;
        await route.fulfill(failed ? { status: 500, json: {} } : { json: result === "missing" ? {} : { markdown: result === "empty" ? "" : "# Recovered report\nActual summary" } });
      });
      await page.goto(url);
      await page.getByText("Download the report for this run", { exact: true }).waitFor();
      await page.getByText("Loading report…", { exact: true }).waitFor();
      assert.equal(await page.getByText("No summary available for this run yet.", { exact: true }).count(), 0);
      const open = page.getByRole("button", { name: /^Download the report for this run/ });
      await open.focus(); await page.keyboard.press("Enter");
      await page.getByRole("heading", { name: "Export report", exact: true }).waitFor();
      assert.equal(await page.getByText("No report is available for this run.", { exact: true }).count(), 0);
      assert.equal(await page.getByRole("link", { name: "Download Markdown" }).count(), 0);
      release();
      if (result === "failure") {
        const alert = page.getByRole("alert").filter({ hasText: "The report could not be loaded" });
        await alert.waitFor();
        assert.equal(await page.getByText("No report is available for this run.", { exact: true }).count(), 0);
        await page.getByRole("button", { name: "Back to results", exact: true }).click();
        assert.equal(await page.getByText("No summary available for this run yet.", { exact: true }).count(), 0);
        failed = false;
        await page.getByRole("alert").filter({ hasText: "The report could not be loaded" }).getByRole("button", { name: "Retry", exact: true }).click();
        await page.getByText("Actual summary", { exact: true }).waitFor();
        await page.getByRole("button", { name: /^Download the report for this run/ }).click();
      }
      if (result === "empty" || result === "missing") {
        await page.getByText("No report is available for this run.", { exact: true }).waitFor();
        await page.getByRole("button", { name: "Back to results", exact: true }).click();
        await page.getByText("No summary available for this run yet.", { exact: true }).waitFor();
      } else await page.getByRole("link", { name: "Download Markdown" }).waitFor();
      assert.equal(await page.getByText("Loading report…", { exact: true }).count(), 0);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    }, viewport));
  }
}

test("report refresh failure retains same-run Markdown in overview and export, but never another run", { timeout: 20000 }, async () => fixture(async (page, url) => {
  let finished = false;
  await page.route(/\/api\/run(?:\?|$)/, async route => {
    const response = await route.fetch();
    await route.fulfill({ json: { ...await response.json(), finished, ...(finished ? { status: "completed" } : {}) } });
  });
  let failed = false;
  let holdHistory = false;
  let release;
  const held = new Promise(resolve => { release = resolve; });
  await page.route("**/api/report*", async route => {
    if (new URL(route.request().url()).searchParams.get("run") === "past-directory") {
      if (holdHistory) await held;
      await route.fulfill({ json: { markdown: "# Historical summary" } });
    } else await route.fulfill(failed ? { status: 500, json: {} } : { json: { markdown: "# Current summary" } });
  });
  await page.goto(url);
  await page.getByRole("button", { name: "Pentest Overview", exact: true }).first().click();
  await page.getByText("Current summary", { exact: true }).waitFor();
  failed = true;
  const alert = page.getByRole("alert").filter({ hasText: "The report could not be loaded" });
  await alert.waitFor();
  assert.equal(await page.getByText("Current summary", { exact: true }).isVisible(), true);
  finished = true;
  await page.getByRole("button", { name: "Export report", exact: true }).click();
  await page.getByRole("link", { name: "Download Markdown" }).waitFor();
  assert.match(await page.getByRole("link", { name: "Download Markdown" }).getAttribute("href"), /Current%20summary/);
  assert.equal(await alert.isVisible(), true);
  failed = false;
  await alert.getByRole("button", { name: "Retry", exact: true }).click();
  await alert.waitFor({ state: "hidden" });
  holdHistory = true;
  const switcher = page.getByRole("combobox", { name: "Switch pentest" });
  await switcher.selectOption("past-directory");
  await page.getByText("Loading report…", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Export report", exact: true }).click();
  assert.equal(await page.getByRole("link", { name: "Download Markdown" }).count(), 0);
  assert.equal(await page.getByText("Current summary", { exact: true }).count(), 0);
  assert.equal(await page.getByText("No report is available for this run.", { exact: true }).count(), 0);
  release();
  await page.getByRole("link", { name: "Download Markdown" }).waitFor();
  assert.match(await page.getByRole("link", { name: "Download Markdown" }).getAttribute("href"), /Historical%20summary/);
}));
