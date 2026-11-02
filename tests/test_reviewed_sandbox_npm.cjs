// Run with `node --test` inside the exact candidate-built sandbox image.
const assert = require("node:assert/strict");
const test = require("node:test");
const path = require("node:path");

const modules = process.env.TASK20_NPM_MODULES || "/home/pentester/.npm-tools/node_modules";
const { expand } = require(path.join(modules, "brace-expansion"));
const hasAddress = require("node:fs").existsSync(path.join(modules, "ip-address"));
const hasFtp = require("node:fs").existsSync(path.join(modules, "basic-ftp"));
const { Address4, Address6 } = hasAddress ? require(path.join(modules, "ip-address")) : {};

test("nested brace input does not exhaust the parser stack", () => {
  assert.doesNotThrow(() => expand("{".repeat(10000) + "a,b" + "}".repeat(10000)));
});

test("IPv6 link-local classification covers the entire fe80::/10 range", { skip: !hasAddress }, () => {
  assert.equal(new Address6("fe90::1").isLinkLocal(), true);
  assert.equal(new Address6("2001:db8::1").isLinkLocal(), false);
});

test("IPv6 addresses cannot enter an IPv4 subnet", { skip: !hasAddress }, () => {
  assert.equal(new Address6("::1").isInSubnet(new Address4("0.0.0.0/0")), false);
});

// Run adversarial parsers out of process so a regression cannot hang the smoke.
const { spawnSync } = require("node:child_process");
function boundedParser(source) {
  const result = spawnSync(process.execPath, ["--max-old-space-size=128", "-e", source], {
    env: { ...process.env, TASK20_NPM_MODULES: modules }, timeout: 2000, encoding: "utf8",
  });
  assert.equal(result.error, undefined, String(result.error));
  assert.equal(result.status, 0, result.stderr);
}

test("FTP rejects adversarial Unix listings within the parser budget", { skip: !hasFtp }, () => {
  boundedParser(`
    const assert = require('node:assert/strict');
    const {parseList} = require(process.env.TASK20_NPM_MODULES + '/basic-ftp/dist/parseList');
    const valid = '-rw-r--r-- 1 owner group 42 Jan 1 2020 file.txt';
    assert.equal(parseList(valid)[0].name, 'file.txt');
    assert.equal(parseList(valid)[0].size, 42);
    try { parseList('-rw-r--r-- 1 ' + 'a '.repeat(65536) + '!\\r\\n' + valid); } catch (e) {
      assert(e instanceof Error);
    }
  `);
});

test("IPv6 rejects oversized zone identifiers within the parser budget", { skip: !hasAddress }, () => {
  boundedParser(`
    const assert = require('node:assert/strict');
    const {Address6} = require(process.env.TASK20_NPM_MODULES + '/ip-address');
    assert.equal(Address6.isValid('%'.repeat(200000) + '\\n'), false);
    assert.equal(new Address6('fe80::1%eth0').zone, '%eth0');
  `);
});

test("Zod short-circuits oversized constrained arrays before item validation", () => {
  const { z } = require(path.join(modules, "zod"));
  let visited = 0;
  const schema = z.array(z.string().superRefine(() => { visited++; })).max(2);
  assert.equal(schema.safeParse(["a", "b"]).success, true);
  visited = 0;
  assert.equal(schema.safeParse(Array(10000).fill("a")).success, false);
  assert.equal(visited, 0);
});

test("glob stops filesystem work after cancellation", async () => {
  const fs = require("node:fs");
  const os = require("node:os");
  const { glob } = require(path.join(modules, "glob"));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-glob-"));
  try {
    for (let i = 0; i < 20; i++) fs.mkdirSync(path.join(dir, `a${i}`, "nested"), {recursive: true});
    const control = new AbortController();
    let reads = 0;
    const wrapped = { ...fs, readdir(...args) {
      reads++;
      if (reads === 1) control.abort(new Error("fixture-abort"));
      return fs.readdir(...args);
    }};
    await assert.rejects(glob("**/*", {cwd: dir, fs: wrapped, signal: control.signal}), /fixture-abort/);
    const atReject = reads;
    await new Promise(resolve => setTimeout(resolve, 100));
    assert.equal(reads, atReject, "cancelled glob must not continue recursive reads");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("minimatch bounds globstar parent preprocessing", () => {
  boundedParser(`
    const assert = require('node:assert/strict');
    const {minimatch} = require(process.env.TASK20_NPM_MODULES + '/minimatch');
    assert.equal(minimatch('src/main.js', '**/*.js', {optimizationLevel: 2}), true);
    assert.equal(minimatch('src/main.py', '**/*.js', {optimizationLevel: 2}), false);
    minimatch('x', ('**/../a/').repeat(22) + 'x', {optimizationLevel: 2});
  `);
});

test("Retire reports a local vulnerable JavaScript library as JSON", () => {
  const fs = require("node:fs");
  const os = require("node:os");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-retire-"));
  try {
    const scan = path.join(dir, "scan"); fs.mkdirSync(scan);
    fs.writeFileSync(path.join(scan, "fixture-1.0.0.js"), "// local scanner fixture");
    const repo = {fixture: {extractors: {filename: ["fixture-(§§version§§)\\.js"]},
      vulnerabilities: [{below: "2.0.0", severity: "high", cwe: ["CWE-79"],
        identifiers: {CVE: ["CVE-2026-0001"]}, info: ["https://example.invalid/advisory"]}]}};
    const repoPath = path.join(dir, "repo.json"); fs.writeFileSync(repoPath, JSON.stringify(repo));
    const result = spawnSync(process.execPath, [path.join(modules, "retire/lib/cli.js"),
      "--path", scan, "--jsrepo", repoPath, "--nocache", "--outputformat", "json", "--severity", "high"],
      {encoding: "utf8", timeout: 10000});
    assert.equal(result.error, undefined);
    assert.equal(result.status, 13, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.data[0].results[0].component, "fixture");
    assert.equal(report.data[0].results[0].vulnerabilities[0].severity, "high");
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test("Retire preserves authenticated HTTP proxy routing", async () => {
  const http = require("node:http");
  const {get} = require(path.join(modules, "retire/lib/http.js"));
  let seen;
  const proxy = http.createServer((req, res) => {
    seen = {url: req.url, auth: req.headers["proxy-authorization"], host: req.headers.host};
    res.end("local repository");
  });
  await new Promise(resolve => proxy.listen(0, "127.0.0.1", resolve));
  try {
    const response = await get("http://example.invalid/repository", {
      proxy: `http://fixture:password@127.0.0.1:${proxy.address().port}`,
    });
    let body = ""; for await (const chunk of response) body += chunk;
    assert.equal(body, "local repository");
    assert.deepEqual(seen, {url: "http://example.invalid/repository", host: "example.invalid",
      auth: "Basic " + Buffer.from("fixture:password").toString("base64")});
  } finally { await new Promise(resolve => proxy.close(resolve)); }
});
