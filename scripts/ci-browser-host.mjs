import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  lstatSync,
  statfsSync,
} from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { createServer } from "node:http";
import { once } from "node:events";
import { FONT_FAMILIES, verifyBitmapFont } from "./ci-browser-fonts.mjs";

const require = createRequire(
  new URL(
    "../lyrashield/interface/viewer/frontend/package.json",
    import.meta.url,
  ),
);
const playwright = require.resolve("playwright/package.json");
const core = createRequire(playwright).resolve("playwright-core/package.json");
const { chromium } = createRequire(core)("playwright-core");

function run(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, `${command} host runtime check failed`);
  return result.stdout;
}

async function verify() {
  assert.equal(process.platform, "linux");
  assert.equal(process.arch, "x64");
  assert.notEqual(process.getuid(), 0);
  assert.equal(JSON.parse(readFileSync(playwright, "utf8")).version, "1.62.1");
  assert.equal(JSON.parse(readFileSync(core, "utf8")).version, "1.62.1");
  const directory = realpathSync(process.argv[2]);
  const manifest = JSON.parse(
    readFileSync(join(directory, "manifest.json"), "utf8"),
  );
  for (const file of manifest.files) {
    const path = join(directory, "fonts", file.path);
    assert.equal(
      createHash("sha256").update(readFileSync(path)).digest("hex"),
      file.sha256,
    );
    // Fontconfig does not decode these legacy X11 PCF encodings, including in
    // the pinned source image. Validate their exact hash and bounded native
    // structure; every scalable Chromium font still must pass fc-scan.
    if (file.path.endsWith(".pcf.gz")) {
      verifyBitmapFont(readFileSync(path));
    } else if (/\.(?:ttf|ttc|otf|pfb|t1)$/.test(file.path))
      assert.ok(
        run("fc-scan", ["--format", "%{family}", path]).trim(),
        "Font asset is unreadable",
      );
  }
  for (const family of FONT_FAMILIES) {
    const [actual, path] = run("fc-match", [
      "--format",
      "%{family}\t%{file}",
      family,
    ]).split("\t");
    assert.ok(actual.includes(family), `${family} is unavailable`);
    assert.ok(
      manifest.files.some(
        (file) => join(directory, "fonts", file.path) === realpathSync(path),
      ),
      `${family} did not resolve to a verified overlay font`,
    );
  }
  const browsers = JSON.parse(
    readFileSync(join(dirname(core), "browsers.json"), "utf8"),
  ).browsers;
  const full = chromium.executablePath();
  assert.ok(full.endsWith("/chromium-1234/chrome-linux64/chrome"));
  const binaries = [
    full,
    join(
      dirname(dirname(dirname(full))),
      "chromium_headless_shell-1234",
      "chrome-headless-shell-linux64",
      "chrome-headless-shell",
    ),
  ];
  for (const name of ["chromium", "chromium-headless-shell"]) {
    const browser = browsers.find((entry) => entry.name === name);
    assert.equal(browser.revision, "1234");
    assert.equal(browser.browserVersion, "151.0.7922.34");
  }
  for (const binary of binaries)
    assert.ok(
      !run("ldd", [binary]).includes("not found"),
      "Host Chromium native library is unavailable",
    );
  const browserTemp = join(directory, "browser-tmp");
  mkdirSync(browserTemp, { mode: 0o700 });
  process.env.TMPDIR = browserTemp;
  let peakTemporaryBytes = 0;
  const bytesIn = (path) =>
    readdirSync(path).reduce((total, name) => {
      const file = join(path, name);
      const stat = lstatSync(file);
      return (
        total +
        (stat.isSymbolicLink()
          ? 0
          : stat.isDirectory()
            ? bytesIn(file)
            : stat.size)
      );
    }, 0);
  const server = createServer((_request, response) =>
    response.end(
      '<!doctype html><meta charset="utf-8"><p>English ไทย 日本語 中文 😀</p>',
    ),
  ).listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    for (const binary of binaries) {
      const browser = await chromium.launch({
        headless: true,
        executablePath: binary,
      });
      try {
        assert.equal(browser.version(), "151.0.7922.34");
        const page = await browser.newPage();
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        assert.equal(
          await page.locator("p").textContent(),
          "English ไทย 日本語 中文 😀",
        );
        await page.close();
        // Exercise the original local artifact lifecycle. Successful traces
        // may grow during a browser lifetime, then must disappear on close.
        for (let iteration = 0; iteration < 3; iteration++) {
          const context = await browser.newContext();
          try {
            await context.tracing.start({ snapshots: true, screenshots: true });
            const probe = await context.newPage();
            await probe.goto(`http://127.0.0.1:${server.address().port}`);
            await probe.screenshot();
            await context.tracing.stop();
            peakTemporaryBytes = Math.max(
              peakTemporaryBytes,
              bytesIn(browserTemp),
            );
          } finally {
            await context.close();
          }
        }
      } finally {
        await browser.close();
      }
      assert.deepEqual(
        readdirSync(browserTemp),
        [],
        "Local browser temporary artifacts were not reclaimed",
      );
    }
  } finally {
    server.close();
    await once(server, "close");
  }
  const available = statfsSync(browserTemp);
  console.log(
    `Verified ${manifest.files.length} pinned font assets, overlay families, host libraries and both local Chromium browsers; bounded lifecycle probe peak=${peakTemporaryBytes} bytes, available=${available.bavail * available.bsize} bytes`,
  );
}

verify().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
