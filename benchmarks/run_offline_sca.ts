/** Exercise the product SCA scanner with one frozen synthetic Composer advisory. */
import { readFile } from "node:fs/promises"
import { createHash } from "node:crypto"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

function arg(name: string): string {
  const index = process.argv.indexOf(`--${name}`)
  if (index < 0 || !process.argv[index + 1]) throw new Error(`missing --${name}`)
  return resolve(process.argv[index + 1]!)
}

function version(value: string): number[] {
  if (!/^\d+\.\d+\.\d+$/.test(value)) throw new Error("unsupported frozen version")
  const parts = value.split(".").map(Number)
  if (!parts.every(Number.isSafeInteger)) throw new Error("unsupported frozen version")
  return parts
}

function before(left: string, right: string): boolean {
  const a = version(left)
  const b = version(right)
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i]! < b[i]!
  }
  return false
}

async function main(): Promise<void> {
  const fixture = arg("fixture")
  const product = process.env.LYRASHIELD_AI_DIR
  if (!product) throw new Error("LYRASHIELD_AI_DIR is required")
  // Do not expose developer credentials or live service configuration to the scanner.
  for (const key of Object.keys(process.env)) {
    if (!["PATH", "TMPDIR"].includes(key)) delete process.env[key]
  }
  Object.assign(process.env, {
    HOME: fixture,
    NODE_ENV: "test",
    DATABASE_URL: "postgresql://fixture:fixture@127.0.0.1:1/fixture",
    BETTER_AUTH_SECRET: "offline-sca-fixture-secret-32-bytes",
    BETTER_AUTH_URL: "http://127.0.0.1:1",
    NEXT_PUBLIC_APP_URL: "http://127.0.0.1:1",
  })
  const snapshotBytes = await readFile(arg("advisories"))
  const corpus = JSON.parse(
    await readFile(fileURLToPath(new URL("./corpus/v3/corpus.json", import.meta.url)), "utf8"),
  )
  if (
    createHash("sha256").update(snapshotBytes).digest("hex") !==
    corpus.contracts?.frozenAdvisories?.sha256
  ) {
    throw new Error("frozen advisory checksum mismatch")
  }
  const snapshot = JSON.parse(snapshotBytes.toString("utf8"))
  const advisory = snapshot.advisories?.[0]
  if (
    snapshot.schemaVersion !== "lyrashield-frozen-advisories/1.0.0" ||
    snapshot.networkRequired !== false ||
    snapshot.advisories.length !== 1 ||
    advisory?.id !== "LYRA-FIXTURE-2026-001" ||
    advisory.ecosystem !== "packagist" ||
    advisory.package !== "example/legacy-router" ||
    advisory.affected !== `<${advisory.fixed}`
  )
    throw new Error("unsupported frozen advisory snapshot")
  version(advisory.fixed)

  let networkAttempts = 0
  const denyNetwork = async (): Promise<never> => {
    networkAttempts++
    throw new Error("network prohibited by offline SCA probe")
  }
  globalThis.fetch = denyNetwork
  const scannerDir = join(resolve(product), "apps/worker/src/engine/scanners")
  const { resolveExactDependencies } = await import(join(scannerDir, "resolved-dependencies"))
  const { scanSca } = await import(join(scannerDir, "sca-scanner"))
  const coverageIssues: unknown[] = []
  const inventory = await resolveExactDependencies({
    repoPath: fixture,
    coverageIssues,
  })
  if (inventory.status !== "COMPLETE" || coverageIssues.length || inventory.packages.length !== 1) {
    throw new Error("incomplete dependency inventory")
  }
  const pkg = inventory.packages[0]
  if (
    pkg.ecosystem !== "Packagist" ||
    pkg.name !== advisory.package ||
    pkg.filePath !== "composer.lock"
  ) {
    throw new Error("unsupported dependency identity")
  }
  const affected = before(pkg.version, advisory.fixed)
  const vulnerability = {
    id: advisory.id,
    summary: "Synthetic frozen advisory for local evaluation only",
    database_specific: { severity: "HIGH" },
    affected: [
      {
        package: { name: pkg.name, ecosystem: pkg.ecosystem },
        ranges: [
          {
            type: "ECOSYSTEM",
            events: [{ introduced: "0" }, { fixed: advisory.fixed }],
          },
        ],
      },
    ],
  }
  const advisoryBatch = {
    status: "COMPLETE",
    results: [{ package: pkg, vulns: affected ? [vulnerability] : [] }],
    unresolved: [],
  }
  const findings = await scanSca({
    repoPath: fixture,
    workspaceDir: fixture,
    resolvedDependencyInventory: inventory,
    advisoryBatch,
    coverageIssues,
    fetchFn: denyNetwork,
  })
  if (networkAttempts || coverageIssues.length) throw new Error("incomplete offline SCA coverage")
  console.log(
    `SCAPROBE:${JSON.stringify({
      inventoryStatus: inventory.status,
      coverageIssues,
      findings: findings.map(
        (finding: {
          id?: string
          target?: string
          dependency_metadata?: {
            package_name?: string
            installed_version?: string
            fixed_version?: string
          }
        }) => ({
          id: finding.id,
          package: finding.dependency_metadata?.package_name,
          version: finding.dependency_metadata?.installed_version,
          fixedVersion: finding.dependency_metadata?.fixed_version,
          file: finding.target,
        }),
      ),
    })}`,
  )
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error))
  process.exitCode = 1
})
