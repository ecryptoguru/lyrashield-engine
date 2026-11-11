/** Invoke the product's owned PostgreSQL/Redis fixture with offline-only tools. */
import { execFile } from "node:child_process"
import { readFile } from "node:fs/promises"
import { lstatSync, realpathSync } from "node:fs"
import { basename, isAbsolute, join, resolve, sep } from "node:path"
import { pathToFileURL } from "node:url"

function arg(name) {
  const index = process.argv.indexOf(`--${name}`)
  if (index < 0 || !process.argv[index + 1]) throw new Error(`missing --${name}`)
  return process.argv[index + 1]
}

const product = resolve(arg("product"))
const docker = resolve(arg("docker"))
const dockerHost = arg("docker-host")
const identity = arg("identity")
if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(identity))
  throw new Error("invalid diagnostic ownership identity")
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
    const label = args[2]
    const envFile = args[6]
    const validEnv =
      image !== "postgres:16-alpine" ||
      (args[5] === "--env-file" &&
        isAbsolute(envFile) &&
        basename(envFile) === "postgres.env" &&
        lstatSync(envFile).isFile() &&
        realpathSync(envFile).startsWith(`${realpathSync(temporary)}${sep}`))
    if (
      !images.has(image) ||
      args.length !== (image === "postgres:16-alpine" ? 8 : 6) ||
      args[1] !== "--label" ||
      !/^lyrashield\.user-scan-slot-fixture=[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
        label
      ) ||
      args[3] !== "--publish" ||
      args[4] !== expectedPort ||
      !validEnv
    ) {
      throw new Error("refusing non-fixture container creation")
    }
    return [
      "create",
      "--pull=never",
      "--label",
      `lyrashield.product-integration-probe=${identity}`,
      ...args.slice(1)
    ]
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
  if ((action === "inspect" || action === "start") && args.length === 2) return args
  if (action === "rm" && args.length === 4 && args[1] === "--force" && args[2] === "--volumes")
    return args
  if (action === "exec") {
    const command = args[args[1] === "-i" ? 3 : 2]
    if (["pg_isready", "psql", "redis-cli"].includes(command)) return args
  }
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
