import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { createConnection } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Official MCR Playwright v1.62.1-jammy, exact Linux amd64 manifest.
// Requalify the image, fonts, native libraries and browser when the lock changes.
export const BROWSER_IMAGE =
  "mcr.microsoft.com/playwright@sha256:75d2d72c89da49d06aa7f6e623987392019aebbc52c09fd8cd6e2c94c7c7d71d";
export const BROWSER_VERSION = "1.62.1";
export const BROWSER_PORT = 31778;
const require = createRequire(
  new URL(
    "../lyrashield/interface/viewer/frontend/package.json",
    import.meta.url,
  ),
);
const label = "lyrashield.engine-ci-browser";
const maxBuffer = 32 * 1024 * 1024;

function runCommand(
  command,
  args,
  { timeout = 30_000, binary = false, input } = {},
) {
  const result = spawnSync(command, args, {
    encoding: binary ? null : "utf8",
    timeout,
    maxBuffer,
    input,
  });
  if (result.error || result.status !== 0) {
    const diagnostic = String(result.stderr ?? "")
      .slice(-4096)
      .trim();
    throw new Error(
      `${command} ${args[0]} failed; exit ${result.status ?? "unavailable"}${result.error ? `; ${result.error.message}` : ""}${diagnostic ? `\n${diagnostic}` : ""}`,
    );
  }
  return result.stdout;
}

function context(env) {
  if (
    env.GITHUB_ACTIONS !== "true" ||
    env.RUNNER_OS !== "Linux" ||
    env.RUNNER_ARCH !== "X64"
  )
    throw new Error("CI browser requires a GitHub Linux X64 runner");
  const scope = `${env.GITHUB_RUN_ID}-${env.GITHUB_RUN_ATTEMPT}-${env.GITHUB_JOB}`;
  if (
    !/^\d+-\d+-[a-zA-Z0-9_-]+$/.test(scope) ||
    !env.RUNNER_TEMP ||
    !env.GITHUB_ENV
  )
    throw new Error("CI browser runner identity is unavailable");
  return {
    scope,
    name: `lyrashield-engine-ci-browser-${scope}`,
    statePath: join(env.RUNNER_TEMP, `engine-ci-browser-${scope}.json`),
  };
}

function packageDirectories() {
  const playwright = require.resolve("playwright/package.json");
  const core = createRequire(playwright).resolve(
    "playwright-core/package.json",
  );
  for (const path of [playwright, core])
    if (JSON.parse(readFileSync(path, "utf8")).version !== BROWSER_VERSION)
      throw new Error(
        "Update and qualify the CI browser image with the Playwright lockfile",
      );
  return [realpathSync(dirname(playwright)), realpathSync(dirname(core))];
}

async function waitForPort() {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const ready = await new Promise((resolveReady) => {
      const socket = createConnection({
        host: "127.0.0.1",
        port: BROWSER_PORT,
      });
      const done = (ready) => {
        socket.destroy();
        resolveReady(ready);
      };
      socket.setTimeout(1000, () => done(false));
      socket.once("error", () => done(false));
      socket.once("connect", () => done(true));
    });
    if (ready) return;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  throw new Error("CI browser loopback server did not become ready");
}

function verifyOwnedContainer(id, ctx, run) {
  if (!/^[a-f0-9]{64}$/.test(id))
    throw new Error("CI browser container identity unavailable");
  const [container] = JSON.parse(run("docker", ["inspect", id]));
  if (
    container.Id !== id ||
    container.Name !== `/${ctx.name}` ||
    container.Config.Labels?.[label] !== ctx.scope ||
    container.Config.Image !== BROWSER_IMAGE
  )
    throw new Error("Refusing to operate on an unowned CI browser container");
}

function findOwnedContainer(ctx, run) {
  const id = run("docker", [
    "ps",
    "--all",
    "--no-trunc",
    "--filter",
    `name=^/${ctx.name}$`,
    "--format",
    "{{.ID}}",
  ]).trim();
  if (id) verifyOwnedContainer(id, ctx, run);
  return id;
}

function ownedState(env, run) {
  const ctx = context(env);
  if (!existsSync(ctx.statePath)) return undefined;
  const state = JSON.parse(readFileSync(ctx.statePath, "utf8"));
  if (state.name !== ctx.name || state.image !== BROWSER_IMAGE)
    throw new Error("CI browser state identity mismatch");
  verifyOwnedContainer(state.id, ctx, run);
  return state;
}

export function stopBrowser({ env = process.env, run = runCommand } = {}) {
  const ctx = context(env);
  const state = ownedState(env, run);
  const id = state?.id || findOwnedContainer(ctx, run);
  if (!id) return;
  run("docker", ["rm", "--force", id]);
  if (state) rmSync(ctx.statePath);
}

export async function startBrowser({
  env = process.env,
  run = runCommand,
  wait = waitForPort,
  packages = packageDirectories,
  writeState = writeFileSync,
} = {}) {
  const ctx = context(env);
  if (existsSync(ctx.statePath))
    throw new Error("CI browser state already exists");
  const dirs = packages();
  run("docker", ["pull", "--platform", "linux/amd64", BROWSER_IMAGE], {
    timeout: 12 * 60_000,
  });
  const [image] = JSON.parse(
    run("docker", ["image", "inspect", BROWSER_IMAGE]),
  );
  if (
    image.Architecture !== "amd64" ||
    image.Os !== "linux" ||
    !image.RepoDigests?.includes(BROWSER_IMAGE)
  )
    throw new Error("CI browser image identity mismatch");
  let id;
  const state = (containerId) =>
    JSON.stringify({ id: containerId, name: ctx.name, image: BROWSER_IMAGE });
  try {
    id = run(
      "docker",
      [
        "run",
        "--detach",
        "--name",
        ctx.name,
        "--label",
        `${label}=${ctx.scope}`,
        "--platform",
        "linux/amd64",
        "--read-only",
        "--user",
        "1000:1000",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--shm-size",
        "512m",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=512m",
        "--network",
        "host",
        "--env",
        "HOME=/tmp",
        BROWSER_IMAGE,
        "node",
        "-e",
        "setInterval(() => {}, 1000)",
      ],
      { timeout: 60_000 },
    ).trim();
    if (!/^[a-f0-9]{64}$/.test(id))
      throw new Error("CI browser container identity unavailable");
    writeState(ctx.statePath, state(id), {
      mode: 0o600,
      flag: "wx",
    });
    run("docker", [
      "exec",
      id,
      "mkdir",
      "-p",
      "/tmp/ci-browser/node_modules/playwright",
      "/tmp/ci-browser/node_modules/playwright-core",
      "/tmp/ci-browser/artifacts",
    ]);
    // docker cp cannot address live tmpfs contents. Stream only the resolved,
    // version-checked packages through the unprivileged container process.
    for (const [index, name] of ["playwright", "playwright-core"].entries()) {
      const archive = run("tar", ["-C", dirs[index], "-cf", "-", "."], {
        binary: true,
      });
      if (archive.length > maxBuffer)
        throw new Error("CI browser package archive is too large");
      run(
        "docker",
        [
          "exec",
          "--interactive",
          "--workdir",
          `/tmp/ci-browser/node_modules/${name}`,
          id,
          "tar",
          "-xf",
          "-",
        ],
        { timeout: 60_000, input: archive },
      );
    }
    run(
      "docker",
      [
        "exec",
        "--interactive",
        id,
        "node",
        "-e",
        'require("fs").writeFileSync("/tmp/ci-browser/container.mjs", require("fs").readFileSync(0))',
      ],
      {
        input: readFileSync(
          new URL("ci-browser-container.mjs", import.meta.url),
        ),
      },
    );
    console.log(
      run(
        "docker",
        ["exec", id, "node", "/tmp/ci-browser/container.mjs", "verify"],
        {
          timeout: 120_000,
        },
      ).trim(),
    );
    // This disposable, unprivileged, mount-free loopback server honors the
    // viewer adapter's launch options. Capture bounded diagnostics on failure.
    run("docker", [
      "exec",
      "--detach",
      id,
      "sh",
      "-c",
      `exec node /tmp/ci-browser/node_modules/playwright/cli.js run-server --host 127.0.0.1 --port ${BROWSER_PORT} --max-clients 4 --artifacts-dir /tmp/ci-browser/artifacts --unsafe > /tmp/ci-browser/server.log 2>&1`,
    ]);
    await wait();
    console.log(
      run(
        "docker",
        ["exec", id, "node", "/tmp/ci-browser/container.mjs", "verify-server"],
        {
          timeout: 60_000,
        },
      ).trim(),
    );
    appendFileSync(
      env.GITHUB_ENV,
      `LYRASHIELD_VIEWER_BROWSER_WS_ENDPOINT=ws://127.0.0.1:${BROWSER_PORT}/\n`,
    );
  } catch (error) {
    // A failed Docker acknowledgement may still have created the container.
    // Resolve only the immutable preselected name, then verify its full ID,
    // label and pinned image. State publication cannot redirect cleanup.
    const cleanupId = /^[a-f0-9]{64}$/.test(id ?? "")
      ? id
      : findOwnedContainer(ctx, run);
    if (cleanupId) {
      verifyOwnedContainer(cleanupId, ctx, run);
      try {
        const diagnostic = run("docker", [
          "exec",
          cleanupId,
          "tail",
          "-c",
          "4096",
          "/tmp/ci-browser/server.log",
        ]).trim();
        if (diagnostic) console.error(diagnostic);
      } catch {
        /* Startup may have failed before the server log exists. */
      }
      run("docker", ["rm", "--force", cleanupId]);
    }
    // Preserve a substituted state file. Only the bytes published for this
    // acknowledged container can be removed after startup fails.
    if (
      id &&
      existsSync(ctx.statePath) &&
      readFileSync(ctx.statePath, "utf8") === state(id)
    )
      rmSync(ctx.statePath);
    throw error;
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    const command = process.argv[2];
    if (command === "start") await startBrowser();
    else if (command === "stop") stopBrowser();
    else throw new Error("Unknown CI browser command");
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
