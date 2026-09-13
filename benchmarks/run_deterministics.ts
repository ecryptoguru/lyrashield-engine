/**
 * Deterministic-scanner benchmark harness — runs the product's deterministic
 * families against corpus fixture directories and emits JSONL findings.
 *
 * Invoked by run.py:
 *   pnpm -C <lyrashield-ai>/apps/worker exec tsx \
 *     ../lyrashield-engine/benchmarks/run_deterministics.ts \
 *     --repo-root <fixtureDir> --scan-id <id>
 *
 * Runs offline: SCA is skipped (no advisory network), the rest run against
 * the materialized fixture directory.
 */
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const args = process.argv.slice(2)
function arg(name: string): string | undefined {
  const i = args.indexOf(`--${name}`)
  return i >= 0 ? args[i + 1] : undefined
}

const fixtureDir = arg("repo-root") ?? ""
const scanId = arg("scan-id") ?? "benchmark"
if (!fixtureDir) {
  console.error("usage: --repo-root <dir>")
  process.exit(2)
}

const SIBLING_PRODUCT = resolve(
  process.env.LYRASHIELD_AI_DIR ?? join(dirname(fileURLToPath(import.meta.url)), "../../lyrashield-ai")
)
const WORKER_SRC = join(SIBLING_PRODUCT, "apps/worker/src")
const scannersDir = join(WORKER_SRC, "engine/scanners")

const { scanSecrets } = await import(join(scannersDir, "secrets-scanner"))
const { scanSast } = await import(join(scannersDir, "sast-scanner"))
const { scanIac } = await import(join(scannersDir, "iac-scanner"))
const { scanAgentConfig } = await import(join(scannersDir, "agent-config-scanner"))
const { scanMlSupplyChain } = await import(join(scannersDir, "ml-supply-chain-scanner"))

async function main(): Promise<void> {
  // The Python runner owns this temporary directory and its cleanup.
  const workspaceDir = resolve(fixtureDir)

  const coverageIssues: unknown[] = []
  const discovery: Record<string, unknown> = {}

  const [secrets, sast, iac, agentConfig, mlSupplyChain] = await Promise.all([
    scanSecrets({ repoPath: workspaceDir, workspaceDir, coverageIssues, discovery }).catch(
      (err: Error) => ({ error: err.message })
    ),
    scanSast({ repoPath: workspaceDir, workspaceDir, mode: "DEEP", coverageIssues, discovery }).catch(
      (err: Error) => ({ error: err.message })
    ),
    scanIac({ repoPath: workspaceDir, workspaceDir, coverageIssues, discovery }).catch(
      (err: Error) => ({ error: err.message })
    ),
    scanAgentConfig({ repoPath: workspaceDir, coverageIssues, discovery }).catch(
      (err: Error) => ({ error: err.message })
    ),
    scanMlSupplyChain({ repoPath: workspaceDir, coverageIssues, discovery }).catch(
      (err: Error) => ({ error: err.message })
    ),
  ])

  const results = [
    { scanner: "secrets", findings: Array.isArray(secrets) ? secrets : [], error: (secrets as { error?: string }).error },
    { scanner: "sast", findings: Array.isArray(sast) ? sast : [], error: (sast as { error?: string }).error },
    { scanner: "iac", findings: Array.isArray(iac) ? iac : [], error: (iac as { error?: string }).error },
    { scanner: "agent_config", findings: Array.isArray(agentConfig) ? agentConfig : [], error: (agentConfig as { error?: string }).error },
    { scanner: "ml_supply_chain", findings: Array.isArray(mlSupplyChain) ? mlSupplyChain : [], error: (mlSupplyChain as { error?: string }).error },
  ]

  for (const { scanner, findings, error } of results) {
    if (error) {
      console.log(JSON.stringify({ scanId, scanner, error }))
      continue
    }
    for (const finding of findings) {
      const loc = (finding as { code_locations?: Array<{ file?: string; start_line?: number }> })
        .code_locations?.[0]
      console.log(
        JSON.stringify({
          scanId,
          scanner,
          id: (finding as { id?: string }).id,
          severity: (finding as { severity?: string }).severity,
          title: (finding as { title?: string }).title,
          cwe: (finding as { cwe?: string }).cwe,
          file: loc?.file ?? (finding as { target?: string }).target ?? null,
          startLine: loc?.start_line ?? null,
        })
      )
    }
  }

  // Discovery + coverage receipts so a bounded run is measurable, not hidden.
  console.log(JSON.stringify({ scanId, scanner: "__discovery__", discovery }))
  console.log(JSON.stringify({ scanId, scanner: "__coverage__", coverageIssues }))
}

await main()
