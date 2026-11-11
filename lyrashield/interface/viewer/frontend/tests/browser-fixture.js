import { chromium } from "playwright";

// Local development keeps the installed browser. CI connects only to the
// exact-owned, digest-qualified server started by scripts/ci-viewer-browser.mjs.
export async function launchViewerBrowser(
  options = {},
  { browserType = chromium, env = process.env } = {},
) {
  const endpoint = env.LYRASHIELD_VIEWER_BROWSER_WS_ENDPOINT;
  if (endpoint === undefined) return browserType.launch(options);
  if (endpoint !== "ws://127.0.0.1:31778/") {
    throw new Error(
      "Viewer browser server must use the qualified CI loopback endpoint",
    );
  }
  return browserType.connect(endpoint, {
    timeout: 30_000,
    // Browser artifacts live in the container's writable temporary directory.
    // Remote download.saveAs() streams bytes to the client; download.path()
    // remains unavailable, as with any remote Playwright connection.
    headers: {
      "x-playwright-launch-options": JSON.stringify({
        ...options,
        artifactsDir: "/tmp/ci-browser/artifacts",
      }),
    },
  });
}
