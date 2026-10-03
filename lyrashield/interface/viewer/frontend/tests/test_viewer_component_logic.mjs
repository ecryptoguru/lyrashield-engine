import assert from "node:assert/strict";
import test from "node:test";

import { getFinishOutcome } from "../src/lib/finish-outcome.ts";
import { resolveFindingTab } from "../src/lib/finding-tabs.ts";
import { getRunStatusDisplay } from "../src/lib/run-status.ts";
import { attemptSteering } from "../src/lib/steering.ts";

test("finish status requires completed status and both persisted completion flags", () => {
  assert.deepEqual(getFinishOutcome("running", {}), { state: "pending" });
  assert.deepEqual(
    getFinishOutcome("completed", { success: true, scan_completed: true }),
    { state: "completed" }
  );
  assert.equal(getFinishOutcome("completed", { success: true }).state, "failed");
  assert.equal(getFinishOutcome("completed", { scan_completed: true }).state, "failed");
  assert.deepEqual(
    getFinishOutcome("failed", { success: true, scan_completed: true, error: "write failed" }),
    { state: "failed", reason: "write failed" }
  );
});

test("finding tabs preserve valid selection and fall back to visible content", () => {
  assert.equal(resolveFindingTab("fix", false, true), "reproduction");
  assert.equal(resolveFindingTab("reproduction", true, false), "fix");
  assert.equal(resolveFindingTab("reproduction", true, true), "reproduction");
  assert.equal(resolveFindingTab("fix", true, true), "fix");
  assert.equal(resolveFindingTab("fix", false, false), "reproduction");
});

test("terminal run states retain distinct labels while unfinished runs stay live", () => {
  assert.deepEqual(getRunStatusDisplay("completed", true), { label: "Complete", tone: "completed" });
  assert.deepEqual(getRunStatusDisplay("failed", true), { label: "Failed", tone: "failed" });
  assert.deepEqual(getRunStatusDisplay("stopped", true), { label: "Stopped", tone: "stopped" });
  assert.deepEqual(getRunStatusDisplay("interrupted", true), { label: "Interrupted", tone: "interrupted" });
  assert.deepEqual(getRunStatusDisplay("failed", false), { label: "Live", tone: "live" });
});

test("steering failures keep a retryable outcome and successful sends are explicit", async () => {
  assert.deepEqual(
    await attemptSteering(async () => { throw new Error("offline"); }, "Root agent"),
    { sent: false, feedback: "Could not send that message. Try again." }
  );
  assert.deepEqual(
    await attemptSteering(async () => ({ ok: false, error: "not_delivered" }), "Child"),
    { sent: false, feedback: "Could not reach that agent (it may have finished)." }
  );
  assert.deepEqual(
    await attemptSteering(async () => ({ ok: true }), "Root agent"),
    { sent: true, feedback: "Sent to Root agent" }
  );
});
