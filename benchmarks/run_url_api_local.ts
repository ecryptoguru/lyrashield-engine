/** Run product scanners through a real scoped relay to a loopback HTTPS fixture. */
import { createHash, randomBytes } from "node:crypto"
import { readFile } from "node:fs/promises"
import {
  createServer as createHttpServer,
  request as httpRequest,
  type IncomingMessage,
  type ServerResponse,
} from "node:http"
import { createServer as createHttpsServer } from "node:https"
import { connect, type AddressInfo } from "node:net"
import { join, resolve } from "node:path"
import type { Duplex } from "node:stream"

function arg(name: string): string {
  const index = process.argv.indexOf(`--${name}`)
  if (index < 0 || !process.argv[index + 1]) throw new Error(`missing --${name}`)
  return resolve(process.argv[index + 1]!)
}

type Relay = {
  register: (scanId: string, grant: string) => { ok: boolean }
  handleForward: (req: IncomingMessage, res: ServerResponse) => Promise<void>
  handleConnect: (req: IncomingMessage, socket: Duplex, head: Buffer) => void
  revoke: (scanId: string) => void
  getAudit: (scanId: string) => unknown
}

async function listen(server: ReturnType<typeof createHttpServer>): Promise<number> {
  await new Promise<void>((resolveReady, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", resolveReady)
  })
  return (server.address() as AddressInfo).port
}

async function close(server: ReturnType<typeof createHttpServer>): Promise<void> {
  if (!server.listening) return
  await new Promise<void>((resolveClose, reject) =>
    server.close((error) => (error ? reject(error) : resolveClose())),
  )
}

function relayServer(relay: Relay) {
  const server = createHttpServer((req, res) => {
    void relay.handleForward(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500)
      res.end()
    })
  })
  server.on("connect", (req, socket, head) => relay.handleConnect(req, socket, head))
  return server
}

async function forward(
  relayPort: number,
  grant: string,
  url: string,
  init: RequestInit = {},
): Promise<Response> {
  const inputHeaders = new Headers(init.headers)
  inputHeaders.delete("host")
  inputHeaders.delete("x-lyra-relay-grant")
  const headers = Object.fromEntries(inputHeaders.entries())
  headers["x-lyra-relay-grant"] = grant
  headers.connection = "close"
  return await new Promise<Response>((resolveResponse, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port: relayPort, method: init.method ?? "GET", path: url, headers },
      (res) => {
        const chunks: Buffer[] = []
        let bytes = 0
        res.on("data", (chunk: Buffer) => {
          bytes += chunk.length
          if (bytes > 1024 * 1024) res.destroy(new Error("fixture response exceeded limit"))
          else chunks.push(chunk)
        })
        res.on("error", reject)
        res.on("end", () => {
          const responseHeaders = new Headers()
          for (const [name, value] of Object.entries(res.headers)) {
            if (value !== undefined && name !== "transfer-encoding") {
              responseHeaders.set(name, Array.isArray(value) ? value.join(", ") : value)
            }
          }
          const body = init.method === "HEAD" ? null : Buffer.concat(chunks)
          resolveResponse(new Response(body, { status: res.statusCode, headers: responseHeaders }))
        })
      },
    )
    const abort = () => req.destroy(new Error("request aborted"))
    req.once("close", () => init.signal?.removeEventListener("abort", abort))
    req.on("error", reject)
    req.setTimeout(5000, () => req.destroy(new Error("relay request timed out")))
    if (init.signal?.aborted) req.destroy(new Error("request aborted"))
    else init.signal?.addEventListener("abort", abort, { once: true })
    req.end()
  })
}

async function connectStatus(relayPort: number, grant: string): Promise<number> {
  return await new Promise((resolveStatus, reject) => {
    const socket = connect(relayPort, "127.0.0.1", () => {
      socket.write(
        `CONNECT fixture.test:443 HTTP/1.1\r\nHost: fixture.test:443\r\n` +
          `Proxy-Authorization: Bearer ${grant}\r\n\r\n`,
      )
    })
    let data = ""
    socket.on("data", (chunk) => {
      data += chunk.toString()
      if (data.includes("\r\n")) {
        socket.destroy()
        resolveStatus(Number(data.split(" ")[1]))
      }
    })
    socket.on("error", reject)
    socket.setTimeout(5000, () => socket.destroy(new Error("CONNECT timed out")))
  })
}

async function main(): Promise<void> {
  const product = process.env.LYRASHIELD_AI_DIR
  if (!product) throw new Error("LYRASHIELD_AI_DIR is required")
  const fixture = arg("fixture")
  const ca = await readFile(arg("ca"), "utf8")
  const wrongCa = await readFile(arg("wrong-ca"), "utf8")
  const cert = await readFile(arg("cert"), "utf8")
  const key = await readFile(arg("key"), "utf8")
  for (const name of Object.keys(process.env)) {
    if (!["PATH", "TMPDIR"].includes(name)) delete process.env[name]
  }
  Object.assign(process.env, {
    HOME: fixture,
    NODE_ENV: "test",
    DATABASE_URL: "postgresql://fixture:fixture@127.0.0.1:1/fixture",
    BETTER_AUTH_SECRET: "url-api-fixture-secret-32-bytes-long",
    BETTER_AUTH_URL: "http://127.0.0.1:1",
    NEXT_PUBLIC_APP_URL: "http://127.0.0.1:1",
  })
  const files = {
    "/": { content: await readFile(join(fixture, "index.html")), type: "text/html" },
    "/openapi.json": {
      content: await readFile(join(fixture, "openapi.json")),
      type: "application/json",
    },
    "/api/health": {
      content: await readFile(join(fixture, "health.json")),
      type: "application/json",
    },
  }
  const targetRequests: Array<{ method: string; path: string }> = []
  const target = createHttpsServer({ key, cert }, (req, res) => {
    const path = new URL(req.url ?? "/", "https://fixture.test").pathname
    targetRequests.push({ method: req.method ?? "", path })
    if (req.headers["x-lyra-relay-grant"] || req.headers["proxy-authorization"]) {
      res.writeHead(500).end("relay credential leaked")
      return
    }
    if (path === "/redirect") {
      res.writeHead(302, { Location: "https://outside.invalid/" }).end()
      return
    }
    const item = files[path as keyof typeof files]
    if (!item) {
      res.writeHead(404).end()
      return
    }
    res.writeHead(200, { "content-type": item.type }).end(item.content)
  })
  const productRoot = resolve(product)
  const { createRelayHandler } = await import(join(productRoot, "packages/egress-proxy/src/relay"))
  const { mintRelayGrant } = await import(join(productRoot, "packages/security/src/relay-grant"))
  const { safeFetchDetailed } = await import(join(productRoot, "packages/security/src/safe-fetch"))
  const { getUrlScanProfile } = await import(
    join(productRoot, "packages/types/src/url-scan-capabilities")
  )
  const scanners = join(productRoot, "apps/worker/src/engine/scanners")
  const { scanUrl } = await import(join(scanners, "url-scanner"))
  const { scanOpenApi } = await import(join(scanners, "openapi-scanner"))
  const targetPort = await listen(target)
  let server: ReturnType<typeof createHttpServer> | undefined
  let untrustedServer: ReturnType<typeof createHttpServer> | undefined
  try {
    const secret = randomBytes(32).toString("hex")
    const scope = {
      v: 1,
      scanId: "local-url-api-diagnostic",
      hosts: ["fixture.test", "wrong.test"],
      methods: ["GET", "HEAD"],
      blockedPaths: ["/admin"],
      exp: Date.now() + 60_000,
      maxRequests: 50,
      maxBytes: 1024 * 1024,
      ratePerMinute: 50,
      perPathPerMinute: 20,
    }
    const grant = mintRelayGrant(scope, secret)
    const dependencies = {
      resolveHost: async (host: string) =>
        ["fixture.test", "wrong.test"].includes(host)
          ? { ok: true, addresses: ["127.0.0.1"] }
          : { ok: false },
      allowedForwardPorts: new Set([targetPort]),
    }
    const relay = createRelayHandler(secret, { ...dependencies, ca }) as Relay
    const untrustedRelay = createRelayHandler(secret, { ...dependencies, ca: wrongCa }) as Relay
    if (
      !relay.register(scope.scanId, grant).ok ||
      !untrustedRelay.register(scope.scanId, grant).ok
    ) {
      throw new Error("fixture grant registration failed")
    }
    server = relayServer(relay)
    untrustedServer = relayServer(untrustedRelay)
    const port = await listen(server)
    const untrustedPort = await listen(untrustedServer)
    const base = `https://fixture.test:${targetPort}`
    const fetchFn = (input: string | URL | Request, init?: RequestInit) =>
      forward(port, grant, input instanceof Request ? input.url : input.toString(), init)
    const resolver = async (host: string) => (host === "fixture.test" ? ["192.0.2.1"] : [])
    const web = await scanUrl({
      targetUrl: `${base}/`,
      profile: getUrlScanProfile("WEB_APP", "SAFE"),
      fetchFn,
      resolver,
    })
    const api = await scanOpenApi({
      targetUrl: `${base}/`,
      apiSpecUrl: `${base}/openapi.json`,
      profile: getUrlScanProfile("API", "STANDARD"),
      fetchFn,
      resolver,
    })
    const allowedResponse = await forward(port, grant, `${base}/api/health`)
    const allowed = allowedResponse.status
    const responseSha256 = createHash("sha256")
      .update(await allowedResponse.text())
      .digest("hex")
    const blockedPath = (await forward(port, grant, `${base}/admin`)).status
    const blockedMethod = (await forward(port, grant, `${base}/api/health`, { method: "POST" }))
      .status
    const blockedHost = (await forward(port, grant, `https://outside.invalid:${targetPort}/`))
      .status
    const blockedPort = (await forward(port, grant, "https://fixture.test:1/")).status
    const opaqueConnect = await connectStatus(port, grant)
    const untrustedCa = (await forward(untrustedPort, grant, `${base}/api/health`)).status
    const wrongHostname = (
      await forward(port, grant, `https://wrong.test:${targetPort}/api/health`)
    ).status
    const redirect = await safeFetchDetailed(`${base}/redirect`, { fetchFn, resolver })
    const externalRedirect = redirect.ok ? "unexpected_success" : redirect.reason
    const invalidGrant = (await forward(port, "invalid", `${base}/api/health`)).status
    relay.revoke(scope.scanId)
    const revokedGrant = (await forward(port, grant, `${base}/api/health`)).status
    const expectedBodySha256 = createHash("sha256")
      .update(files["/api/health"].content)
      .digest("hex")
    const audit = relay.getAudit(scope.scanId) as Array<{ denyReason?: string }> | null
    const denied = new Set(audit?.map((entry) => entry.denyReason))
    if (
      web.execution.profile !== "WEB_APP_SAFE" ||
      web.execution.documentCount !== 1 ||
      web.execution.issueCodes.length ||
      api.execution.profile !== "API_STANDARD" ||
      api.execution.operationCount !== 2 ||
      api.execution.issueCodes.length ||
      api.attemptedOperations.length !== 2 ||
      api.attemptedOperations[0].method !== "GET" ||
      api.attemptedOperations[0].path !== "/api/health" ||
      api.attemptedOperations[1].method !== "HEAD" ||
      api.attemptedOperations[1].path !== "/api/health" ||
      allowed !== 200 ||
      responseSha256 !== expectedBodySha256 ||
      blockedPath !== 403 ||
      blockedMethod !== 403 ||
      blockedHost !== 403 ||
      blockedPort !== 403 ||
      opaqueConnect !== 403 ||
      invalidGrant !== 403 ||
      revokedGrant !== 403 ||
      untrustedCa !== 502 ||
      wrongHostname !== 502 ||
      externalRedirect !== "ssrf_blocked" ||
      ![
        "path_blocked",
        "method_not_allowed",
        "host_out_of_scope",
        "port_not_allowed",
        "connect_not_supported",
        "revoked",
      ].every((reason) => denied.has(reason)) ||
      targetRequests.some(
        ({ method, path }) =>
          !["GET", "HEAD"].includes(method) ||
          !["/", "/openapi.json", "/api/health", "/redirect"].includes(path),
      )
    )
      throw new Error("incomplete local URL/API diagnostic")
    const result = {
      web: {
        profile: web.execution.profile,
        documentCount: web.execution.documentCount,
        issueCodes: web.execution.issueCodes,
        findings: web.findings,
      },
      api: {
        profile: api.execution.profile,
        operationCount: api.execution.operationCount,
        findings: api.findings,
        operations: api.attemptedOperations.map(
          ({ method, path }: { method: string; path: string }) => ({ method, path }),
        ),
        issueCodes: api.execution.issueCodes,
      },
      checks: {
        allowed,
        blockedPath,
        blockedMethod,
        blockedHost,
        blockedPort,
        opaqueConnect,
        invalidGrant,
        revokedGrant,
        untrustedCa,
        wrongHostname,
        externalRedirect,
      },
      scope,
      scopeGrantSha256: createHash("sha256").update(grant).digest("hex"),
      targetIdentity: {
        host: "fixture.test",
        port: targetPort,
        certificateSha256: createHash("sha256").update(cert).digest("hex"),
      },
      responseSha256,
      relayAudit: audit,
      untrustedRelayAudit: untrustedRelay.getAudit(scope.scanId),
      targetRequests,
    }
    console.log(`URLPROBE:${JSON.stringify(result)}`)
  } finally {
    await Promise.all([
      ...(server ? [close(server)] : []),
      ...(untrustedServer ? [close(untrustedServer)] : []),
      close(target),
    ])
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error))
  process.exitCode = 1
})
