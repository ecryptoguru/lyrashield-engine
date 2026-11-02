import { spawn } from "node:child_process";
import { once } from "node:events";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../../../", import.meta.url));
const python = resolve(root, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");

async function stop(server) {
  if (!server.pid || server.exitCode !== null || server.signalCode !== null) return;
  const closed = once(server, "close", { signal: AbortSignal.timeout(1000) });
  server.kill("SIGTERM");
  try {
    await closed;
  } catch (error) {
    if (error.name !== "AbortError") throw error;
    const killed = once(server, "close", { signal: AbortSignal.timeout(1000) });
    server.kill("SIGKILL");
    await killed;
  }
}

export async function startPythonServer(script, args = [], {
  executable = python, startupTimeout = 10_000,
} = {}) {
  const server = spawn(executable, [resolve(root, script), ...args], {
    cwd: root, env: { ...process.env, PYTHONPATH: root }, stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "", stdout = "", timer;
  server.stderr.on("data", chunk => { stderr = (stderr + chunk).slice(-4096); });
  const ready = new Promise((resolveReady, reject) => {
    server.on("error", reject);
    server.once("exit", (code, signal) => reject(new Error(`exited before readiness (${signal ?? code})`)));
    server.stdout.on("data", chunk => {
      stdout += chunk;
      if (stdout.length > 16_384) {
        reject(new Error("oversized readiness record"));
        return;
      }
      if (!stdout.includes("\n")) return;
      try {
        const record = JSON.parse(stdout.split("\n", 1)[0]);
        if (typeof record.url !== "string") throw new Error("readiness record has no URL");
        resolveReady(record);
      } catch (error) { reject(error); }
    });
    timer = setTimeout(() => reject(new Error(`no readiness record within ${startupTimeout}ms`)), startupTimeout);
  });
  try {
    const record = await ready;
    return { ...record, stop: () => stop(server) };
  } catch (error) {
    await stop(server);
    throw new Error(`Python viewer fixture ${script}: ${error.message}${stderr ? `\n${stderr}` : ""}`, { cause: error });
  } finally {
    clearTimeout(timer);
  }
}
