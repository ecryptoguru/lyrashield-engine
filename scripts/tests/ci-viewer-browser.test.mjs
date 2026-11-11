import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createFontArchive,
  FONT_COMPRESSED_LIMIT,
} from "../ci-browser-fonts.mjs";
import {
  BROWSER_IMAGE,
  BROWSER_VERSION,
  startBrowser,
  stopBrowser,
} from "../ci-viewer-browser.mjs";

const id = "a".repeat(64);
function fixture(options = {}) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "ci-browser-test-")));
  const env = {
    GITHUB_ACTIONS: "true",
    RUNNER_OS: "Linux",
    RUNNER_ARCH: "X64",
    GITHUB_RUN_ID: "123",
    GITHUB_RUN_ATTEMPT: "2",
    GITHUB_JOB: "app-core-tests",
    RUNNER_TEMP: dir,
    GITHUB_ENV: join(dir, "env"),
    GITHUB_PATH: join(dir, "path"),
    BREVO_API_KEY: "must-not-enter-container",
    DATABASE_URL: "must-not-enter-container",
  };
  const calls = [];
  let removed = false;
  let searches = 0;
  const run = (command, args, config = {}) => {
    calls.push({ command, args, config });
    if (args.includes("font-archive")) {
      if (options.failTransfer) throw new Error("font archive transfer failed");
      return createFontArchive([
        {
          path: "truetype/freefont/FreeSans.ttf",
          bytes: Buffer.from("verified-font-fixture"),
        },
      ]);
    }
    if (command === "node" && args[0].endsWith("ci-browser-host.mjs")) {
      if (options.substituteState) {
        writeFileSync(
          join(dir, "engine-ci-browser-123-2-app-core-tests.json"),
          options.substituteState,
        );
        throw new Error("host unavailable after state substitution");
      }
      if (options.failHost) throw new Error("host native runtime unavailable");
    }
    if (command === "node" && args.includes("install") && options.failInstall)
      throw new Error("browser binary install unavailable");
    if (args[0] === "image")
      return JSON.stringify([
        {
          Architecture: options.arch ?? "amd64",
          Os: "linux",
          RepoDigests: [options.image ?? BROWSER_IMAGE],
        },
      ]);
    if (args[0] === "run") {
      if (options.missingStateDirectory) rmSync(dir, { recursive: true });
      if (options.lostAcknowledgement)
        throw new Error("Docker create acknowledgement lost");
      return options.badAcknowledgement ? "unusable-id" : `${id}\n`;
    }
    if (args[0] === "ps") {
      searches++;
      return removed ||
        options.noContainer ||
        (options.delayedCreation && searches === 1)
        ? ""
        : `${id}\n`;
    }
    if (args[0] === "rm") removed = true;
    if (args[0] === "inspect")
      return JSON.stringify([
        {
          Id: id,
          Name: "/lyrashield-engine-ci-browser-123-2-app-core-tests",
          Config: {
            Image: BROWSER_IMAGE,
            Labels: {
              "lyrashield.engine-ci-browser": options.foreign
                ? "other-run"
                : "123-2-app-core-tests",
            },
          },
        },
      ]);
    if (args.includes("verify") && options.failVerify)
      throw new Error("native dependency missing");
    if (config.binary)
      return options.bytes ?? Buffer.from("0000ftyp000000000000000000000000");
    return "";
  };
  const input = {
    env,
    run,
    packages: () => ["/locked/playwright", "/locked/playwright-core"],
  };
  return {
    dir,
    env,
    run,
    calls,
    input,
    clean: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test("extracts pinned fonts and verifies the unchanged local browser runtime", async () => {
  const f = fixture();
  try {
    await startBrowser(f.input);
    const pull = f.calls.find((call) => call.args[0] === "pull");
    assert.deepEqual(pull.args, [
      "pull",
      "--platform",
      "linux/amd64",
      BROWSER_IMAGE,
    ]);
    const args = f.calls.find((call) => call.args[0] === "run").args;
    for (const [flag, value] of [
      ["--user", "1000:1000"],
      ["--cap-drop", "ALL"],
      ["--network", "none"],
      ["--security-opt", "no-new-privileges"],
      ["--tmpfs", "/tmp:rw,nosuid,nodev,size=512m"],
    ])
      assert.equal(args[args.indexOf(flag) + 1], value);
    assert.ok(args.includes("--read-only"));
    assert.ok(args.includes("--init"));
    for (const forbidden of [
      "--privileged",
      "--mount",
      "-v",
      "--ipc",
      "--env-file",
      f.env.BREVO_API_KEY,
      f.env.DATABASE_URL,
      "/var/run/docker.sock",
    ])
      assert.ok(!args.includes(forbidden), forbidden);
    assert.deepEqual(
      args.slice(args.indexOf("--env"), args.indexOf("--env") + 2),
      ["--env", "HOME=/tmp"],
    );
    assert.ok(
      !f.calls.some(
        (call) =>
          call.args.some((arg) => arg.includes("run-server")) ||
          call.args.includes("--unsafe"),
      ),
    );
    const host = f.calls.find(
      (call) =>
        call.command === "node" && call.args[0].endsWith("ci-browser-host.mjs"),
    );
    const config = host.config.env.FONTCONFIG_FILE;
    assert.equal(
      readFileSync(f.env.GITHUB_ENV, "utf8"),
      `FONTCONFIG_FILE=${config}\n`,
    );
    assert.ok(!readFileSync(f.env.GITHUB_ENV, "utf8").includes("WS_ENDPOINT"));
    assert.ok(readFileSync(config, "utf8").includes("/etc/fonts/fonts.conf"));
    assert.deepEqual(
      f.calls.find(
        (call) => call.command === "node" && call.args.includes("install"),
      ).args,
      ["/locked/playwright/cli.js", "install", "chromium"],
    );
    const archiveCall = f.calls.find((call) =>
      call.args.includes("font-archive"),
    );
    assert.equal(archiveCall.config.outputLimit, FONT_COMPRESSED_LIMIT);
    assert.ok(
      f.calls
        .filter((call) => call !== archiveCall)
        .every((call) => call.config.outputLimit === undefined),
    );
    const transfers = f.calls.filter((call) =>
      call.args.includes("--interactive"),
    );
    assert.equal(transfers.length, 2);
    assert.ok(transfers.every((call) => Buffer.isBuffer(call.config.input)));
    assert.ok(
      !f.calls.some((call) => call.command === "tar" || call.args[0] === "cp"),
    );
    stopBrowser(f.input);
    assert.deepEqual(f.calls.at(-1).args, ["rm", "--force", id]);
    // Overlay deletion is delegated to GitHub RUNNER_TEMP cleanup, not state.
    assert.ok(existsSync(config));
    stopBrowser(f.input);
  } finally {
    f.clean();
  }
});

for (const failure of ["failTransfer", "failVerify", "failInstall", "failHost"])
  test(`${failure} fails closed, removes only its container and publishes no font configuration`, async () => {
    const f = fixture({ [failure]: true });
    try {
      await assert.rejects(startBrowser(f.input));
      assert.deepEqual(f.calls.at(-1).args, ["rm", "--force", id]);
      assert.equal(existsSync(f.env.GITHUB_ENV), false);
    } finally {
      f.clean();
    }
  });

test("ENOENT while publishing state still removes the exact owned container", async () => {
  const f = fixture({ missingStateDirectory: true });
  try {
    await assert.rejects(startBrowser(f.input), { code: "ENOENT" });
    assert.deepEqual(f.calls.at(-1).args, ["rm", "--force", id]);
    assert.ok(!f.calls.some((call) => call.args.includes("verify")));
  } finally {
    f.clean();
  }
});

test("ENOSPC while publishing state still removes the exact owned container", async () => {
  const f = fixture();
  try {
    await assert.rejects(
      startBrowser({
        ...f.input,
        writeState: () => {
          throw Object.assign(new Error("state disk full"), { code: "ENOSPC" });
        },
      }),
      { code: "ENOSPC" },
    );
    assert.deepEqual(f.calls.at(-1).args, ["rm", "--force", id]);
    assert.equal(existsSync(f.env.GITHUB_ENV), false);
  } finally {
    f.clean();
  }
});

test("foreign state substitution cannot redirect startup cleanup", async () => {
  const foreign = JSON.stringify({
    id: "b".repeat(64),
    name: "lyrashield-engine-ci-browser-123-2-app-core-tests",
    image: BROWSER_IMAGE,
  });
  const f = fixture({ substituteState: foreign });
  try {
    await assert.rejects(startBrowser(f.input), /state substitution/);
    assert.deepEqual(f.calls.at(-1).args, ["rm", "--force", id]);
    assert.equal(
      readFileSync(
        join(f.dir, "engine-ci-browser-123-2-app-core-tests.json"),
        "utf8",
      ),
      foreign,
    );
  } finally {
    f.clean();
  }
});

for (const option of ["lostAcknowledgement", "badAcknowledgement"])
  test(`${option} resolves only the preselected name and removes its verified full ID`, async () => {
    const f = fixture({ [option]: true });
    try {
      await assert.rejects(startBrowser(f.input));
      assert.deepEqual(f.calls.find((call) => call.args[0] === "ps").args, [
        "ps",
        "--all",
        "--no-trunc",
        "--filter",
        "name=^/lyrashield-engine-ci-browser-123-2-app-core-tests$",
        "--format",
        "{{.ID}}",
      ]);
      assert.deepEqual(f.calls.at(-1).args, ["rm", "--force", id]);
      assert.equal(existsSync(f.env.GITHUB_ENV), false);
    } finally {
      f.clean();
    }
  });

test("ambiguous creation refuses a foreign container at the preselected name", async () => {
  const f = fixture({ lostAcknowledgement: true, foreign: true });
  try {
    await assert.rejects(startBrowser(f.input), /unowned/);
    assert.ok(!f.calls.some((call) => call.args[0] === "rm"));
  } finally {
    f.clean();
  }
});

test("lost acknowledgement with no created container needs no deletion", async () => {
  const f = fixture({ lostAcknowledgement: true, noContainer: true });
  try {
    await assert.rejects(startBrowser(f.input), /acknowledgement lost/);
    assert.ok(!f.calls.some((call) => call.args[0] === "rm"));
  } finally {
    f.clean();
  }
});

test("always cleanup can find late creation without any published state", async () => {
  const f = fixture({ lostAcknowledgement: true, delayedCreation: true });
  try {
    await assert.rejects(startBrowser(f.input), /acknowledgement lost/);
    assert.ok(!f.calls.some((call) => call.args[0] === "rm"));
    stopBrowser(f.input);
    assert.deepEqual(f.calls.at(-1).args, ["rm", "--force", id]);
    stopBrowser(f.input);
    assert.equal(f.calls.filter((call) => call.args[0] === "rm").length, 1);
  } finally {
    f.clean();
  }
});

for (const option of [{ arch: "arm64" }, { image: "unqualified" }])
  test(`rejects unqualified image ${JSON.stringify(option)}`, async () => {
    const f = fixture(option);
    try {
      await assert.rejects(startBrowser(f.input), /image identity/);
      assert.ok(!f.calls.some((call) => call.args[0] === "run"));
    } finally {
      f.clean();
    }
  });

test("refuses foreign-container cleanup", async () => {
  const f = fixture({ foreign: true });
  try {
    await startBrowser(f.input);
    assert.throws(() => stopBrowser(f.input), /unowned/);
    assert.ok(!f.calls.some((call) => call.args[0] === "rm"));
  } finally {
    f.clean();
  }
});

test("refuses non-GitHub or non-Linux/X64 execution before Docker", async () => {
  for (const change of [
    { GITHUB_ACTIONS: "false" },
    { RUNNER_OS: "macOS" },
    { RUNNER_ARCH: "ARM64" },
  ]) {
    const f = fixture();
    try {
      await assert.rejects(
        startBrowser({ ...f.input, env: { ...f.env, ...change } }),
        /Linux X64/,
      );
      assert.equal(f.calls.length, 0);
    } finally {
      f.clean();
    }
  }
});

test("qualified browser version matches both frozen frontend package locks", () => {
  const manifest = JSON.parse(
    readFileSync(
      new URL(
        "../../lyrashield/interface/viewer/frontend/package.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  const lock = JSON.parse(
    readFileSync(
      new URL(
        "../../lyrashield/interface/viewer/frontend/package-lock.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.equal(manifest.devDependencies.playwright, BROWSER_VERSION);
  for (const name of ["playwright", "playwright-core"])
    assert.equal(
      lock.packages[`node_modules/${name}`].version,
      BROWSER_VERSION,
    );
});

test("existing state fails before Docker and preserves the original receipt", async () => {
  const f = fixture();
  const path = join(f.dir, "engine-ci-browser-123-2-app-core-tests.json");
  try {
    writeFileSync(path, "existing receipt");
    await assert.rejects(startBrowser(f.input), /state already exists/);
    assert.deepEqual(f.calls, []);
    assert.equal(readFileSync(path, "utf8"), "existing receipt");
  } finally {
    f.clean();
  }
});

test("endpoint publication failure cleans up the exact acknowledged container", async () => {
  const f = fixture();
  try {
    f.env.GITHUB_ENV = join(f.dir, "missing", "env");
    await assert.rejects(startBrowser(f.input), { code: "ENOENT" });
    assert.deepEqual(f.calls.at(-1).args, ["rm", "--force", id]);
    assert.equal(
      existsSync(join(f.dir, "engine-ci-browser-123-2-app-core-tests.json")),
      false,
    );
  } finally {
    f.clean();
  }
});
