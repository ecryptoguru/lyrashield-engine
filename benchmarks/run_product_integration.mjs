/** Invoke the product's owned PostgreSQL/Redis fixture with offline-only tools. */
import { execFile } from "node:child_process"
import { readFile } from "node:fs/promises"
import { join, resolve } from "node:path"
import { pathToFileURL } from "node:url"

function arg(name) {
  const index = process.argv.indexOf(`--${name}`)
  if (index < 0 || !process.argv[index + 1]) throw new Error(`missing --${name}`)
  return process.argv[index + 1]
}

const product = resolve(arg("product"))
const docker = resolve(arg("docker"))
const dockerHost = arg("docker-host")
const pnpm = resolve(arg("pnpm"))
const corepackHome = resolve(arg("corepack-home"))
const temporary = resolve(arg("temporary"))
const report = resolve(arg("report"))
const node = process.execPath
if (!dockerHost.startsWith("unix:///")) throw new Error("local Unix Docker context required")

const images = new Set(["postgres:16-alpine", "redis:7-alpine"])
const owned = new Set()
const removed = new Set()
const observed = []

function dockerArguments(args) {
  const [action] = args
  if (
    action === "context" &&
    args.join(" ") === "context inspect --format {{json .Endpoints.docker.Host}}"
  ) {
    return args
  }
  if (action === "create") {
    const image = args.at(-1)
    const expectedPort = image === "postgres:16-alpine" ? "127.0.0.1::5432" : "127.0.0.1::6379"
    if (!images.has(image) || !args.includes(expectedPort) || args.includes("--network=host")) {
      throw new Error("refusing non-fixture container creation")
    }
    return ["create", "--pull=never", ...args.slice(1)]
  }
  const containerId =
    action === "inspect" || action === "start"
      ? args[1]
      : action === "exec"
        ? args[args[1] === "-i" ? 2 : 1]
        : action === "rm"
          ? args.at(-1)
          : undefined
  if (!containerId || !owned.has(containerId))
    throw new Error("refusing non-owned Docker operation")
  if (action === "inspect" || action === "start" || action === "exec" || action === "rm")
    return args
  throw new Error("unsupported Docker operation")
}

async function run(binary, args, options = {}) {
  if (binary !== "docker" && binary !== "pnpm") throw new Error("unsupported fixture command")
  const isDocker = binary === "docker"
  const actualArgs = isDocker ? dockerArguments(args) : [pnpm, ...args]
  const env = {
    ...options.env,
    PATH: `${resolve(node, "..")}:/usr/bin:/bin`,
    HOME: temporary,
    TMPDIR: temporary,
    ...(isDocker
      ? { DOCKER_HOST: dockerHost, DOCKER_CONFIG: join(temporary, "docker-config") }
      : {
          COREPACK_HOME: corepackHome,
          COREPACK_ENABLE_NETWORK: "0",
          npm_config_offline: "true",
          PRISMA_ENGINES_MIRROR: "http://127.0.0.1:1",
        }),
  }
  const stdout = await new Promise((accept, reject) => {
    const child = execFile(
      isDocker ? docker : node,
      actualArgs,
      { cwd: product, env, signal: options.signal, timeout: 180_000, maxBuffer: 16 * 1024 * 1024 },
      (error, out, err) => {
        if (options.verbose || error) {
          process.stdout.write(out)
          process.stderr.write(err)
        }
        if (error) reject(error)
        else accept(out.trim())
      },
    )
    child.stdin.end(options.input)
  })
  if (isDocker && args[0] === "create") {
    if (!/^[a-f0-9]{64}$/.test(stdout)) throw new Error("invalid fixture container identity")
    owned.add(stdout)
    console.log(`OWNED_CREATED:${stdout}`)
  }
  if (isDocker && args[0] === "inspect") {
    const record = JSON.parse(stdout)[0]
    observed.push({ containerId: record.Id, imageTag: record.Config.Image, imageId: record.Image })
  }
  if (isDocker && args[0] === "rm") {
    removed.add(args.at(-1))
    console.log(`OWNED_REMOVED:${args.at(-1)}`)
  }
  return stdout
}

const controller = new AbortController()
const interrupt = () => controller.abort()
process.once("SIGINT", interrupt)
process.once("SIGTERM", interrupt)
try {
  const { runUserScanSlotRuntime } = await import(
    pathToFileURL(join(product, ".github/scripts/run-user-scan-slot-runtime.mjs")).href
  )
  await runUserScanSlotRuntime({
    run,
    source: { PATH: `${resolve(node, "..")}:/usr/bin:/bin`, HOME: temporary, TMPDIR: temporary },
    reportPath: report,
    signal: controller.signal,
  })
  if (owned.size !== 2 || removed.size !== 2 || [...owned].some((id) => !removed.has(id))) {
    throw new Error("owned fixture cleanup was not confirmed")
  }
  const reportBytes = await readFile(report)
  const summary = JSON.parse(reportBytes.toString("utf8"))
  console.log(
    `PRODUCTPROBE:${JSON.stringify({
      observed,
      containersCreated: owned.size,
      containersRemoved: removed.size,
      report: {
        total: summary.numTotalTests,
        passed: summary.numPassedTests,
        failed: summary.numFailedTests,
        skipped: summary.numPendingTests,
      },
    })}`,
  )
} finally {
  process.removeListener("SIGINT", interrupt)
  process.removeListener("SIGTERM", interrupt)
}
