// Run with `node --test` inside the exact candidate-built sandbox image.
const assert = require("node:assert/strict");
const test = require("node:test");
const path = require("node:path");

const modules = process.env.TASK20_NPM_MODULES || "/home/pentester/.npm-tools/node_modules";
const { expand } = require(path.join(modules, "brace-expansion"));
const { Address4, Address6 } = require(path.join(modules, "ip-address"));

test("nested brace input does not exhaust the parser stack", () => {
  assert.doesNotThrow(() => expand("{".repeat(10000) + "a,b" + "}".repeat(10000)));
});

test("IPv6 link-local classification covers the entire fe80::/10 range", () => {
  assert.equal(new Address6("fe90::1").isLinkLocal(), true);
  assert.equal(new Address6("2001:db8::1").isLinkLocal(), false);
});

test("IPv6 addresses cannot enter an IPv4 subnet", () => {
  assert.equal(new Address6("::1").isInSubnet(new Address4("0.0.0.0/0")), false);
});
