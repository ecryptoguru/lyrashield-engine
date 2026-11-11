import test from "node:test";
import assert from "node:assert/strict";
import { launchViewerBrowser } from "./browser-fixture.js";

function fixture(env) {
  const calls = [];
  const browser = { close: async () => {} };
  const browserType = {
    launch: async (...args) => {
      calls.push(["launch", ...args]);
      return browser;
    },
    connect: async (...args) => {
      calls.push(["connect", ...args]);
      return browser;
    },
  };
  return { calls, browser, input: { browserType, env } };
}

test("local viewer launch preserves every option and returns the closable browser", async () => {
  const f = fixture({});
  const options = { headless: true, args: ["--lang=en-US"], timeout: 1234 };
  assert.equal(await launchViewerBrowser(options, f.input), f.browser);
  assert.deepEqual(f.calls, [["launch", options]]);
});

test("remote viewer launch preserves options with server-owned artifacts", async () => {
  const endpoint = "ws://127.0.0.1:31778/";
  const f = fixture({ LYRASHIELD_VIEWER_BROWSER_WS_ENDPOINT: endpoint });
  const options = {
    headless: true,
    args: ["--force-color-profile=srgb"],
    timeout: 1234,
    artifactsDir: "/client/artifacts",
  };
  assert.equal(await launchViewerBrowser(options, f.input), f.browser);
  assert.equal(f.calls.length, 1);
  const [method, actualEndpoint, connection] = f.calls[0];
  assert.equal(method, "connect");
  assert.equal(actualEndpoint, endpoint);
  assert.equal(connection.timeout, 30_000);
  assert.deepEqual(
    JSON.parse(connection.headers["x-playwright-launch-options"]),
    {
      ...options,
      artifactsDir: "/tmp/ci-browser/artifacts",
    },
  );
  assert.equal(options.artifactsDir, "/client/artifacts");
});

for (const endpoint of [
  "",
  "ws://example.com:31778/",
  "ws://127.0.0.1:31779/",
  "ws://localhost:31778/",
  "ws://user:pass@127.0.0.1:31778/",
  "ws://127.0.0.1:31778/?token=unexpected",
  "wss://127.0.0.1:31778/",
]) {
  test(`viewer adapter rejects unqualified endpoint ${endpoint}`, async () => {
    const f = fixture({ LYRASHIELD_VIEWER_BROWSER_WS_ENDPOINT: endpoint });
    await assert.rejects(
      launchViewerBrowser({}, f.input),
      /qualified CI loopback/,
    );
    assert.deepEqual(f.calls, []);
  });
}

test("remote launch failure propagates without falling back to another browser", async () => {
  const f = fixture({
    LYRASHIELD_VIEWER_BROWSER_WS_ENDPOINT: "ws://127.0.0.1:31778/",
  });
  f.input.browserType.connect = async () => {
    throw new Error("qualified server unavailable");
  };
  await assert.rejects(
    launchViewerBrowser({}, f.input),
    /qualified server unavailable/,
  );
  assert.deepEqual(f.calls, []);
});
