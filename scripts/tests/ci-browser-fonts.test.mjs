import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync, gunzipSync } from "node:zlib";
import {
  FONT_DATA_LIMIT,
  FONT_COMPRESSED_LIMIT,
  createFontArchive,
  readFontArchive,
  unpackFonts,
  fontconfigOverlay,
} from "../ci-browser-fonts.mjs";

const font = {
  path: "truetype/freefont/FreeSans.ttf",
  bytes: Buffer.from("font fixture"),
};

test("extracts only manifest-verified regular font bytes", () => {
  const directory = mkdtempSync(join(tmpdir(), "ci-fonts-archive-test-"));
  try {
    const manifest = unpackFonts(createFontArchive([font]), directory);
    assert.equal(manifest.files.length, 1);
    assert.deepEqual(readFileSync(join(directory, font.path)), font.bytes);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

for (const path of [
  "../escape.ttf",
  "/escape.ttf",
  "truetype/../escape.ttf",
  "truetype//escape.ttf",
  "truetype/a\\b.ttf",
  "etc/fonts/fonts.conf",
  "truetype/font.so",
])
  test(`rejects archive path ${path}`, () =>
    assert.throws(
      () => readFontArchive(createFontArchive([{ ...font, path }])),
      /allowlist/,
    ));

for (const type of ["1", "2", "3", "4", "5", "6", "S", "x", "L"])
  test(`rejects link/special/sparse/extended entry type ${type}`, () => {
    const bytes = gunzipSync(createFontArchive([font]));
    bytes[156] = type.charCodeAt(0);
    assert.throws(
      () => readFontArchive(gzipSync(bytes)),
      /link, sparse or special/,
    );
  });

test("rejects duplicates and corrupted manifest data", () => {
  assert.throws(
    () => readFontArchive(createFontArchive([font, font])),
    /Duplicate/,
  );
  const bytes = gunzipSync(createFontArchive([font]));
  bytes[1536] ^= 1;
  assert.throws(() => readFontArchive(gzipSync(bytes)), /integrity/);
});

test("rejects damaged headers, truncation and nonzero trailing data", () => {
  const bytes = gunzipSync(createFontArchive([font]));
  const damaged = Buffer.from(bytes);
  damaged[100] ^= 1;
  assert.throws(() => readFontArchive(gzipSync(damaged)), /checksum/);
  assert.throws(
    () => readFontArchive(gzipSync(bytes.subarray(0, 1600))),
    /Truncated|trailer/,
  );
  assert.throws(
    () =>
      readFontArchive(gzipSync(Buffer.concat([bytes, Buffer.from("hidden")]))),
    /trailer/,
  );
});

test("caps compressed and expanded archive data", () => {
  assert.throws(
    () => readFontArchive(Buffer.alloc(FONT_COMPRESSED_LIMIT + 1)),
    /compressed size/,
  );
  assert.throws(() =>
    readFontArchive(gzipSync(Buffer.alloc(128 * 1024 * 1024 + 512))),
  );
});

test("private fontconfig keeps host rules, gives its cache priority and escapes XML paths", () => {
  const config = fontconfigOverlay('/tmp/owned&fonts"', "/tmp/cache<private>");
  assert.ok(
    config.includes(
      '<include ignore_missing="no">/etc/fonts/fonts.conf</include>',
    ),
  );
  assert.ok(config.indexOf("<cachedir>") < config.indexOf("<include"));
  assert.ok(config.includes("<reset-dirs/>"));
  assert.ok(config.includes("owned&amp;fonts&quot;"));
  assert.ok(config.includes("cache&lt;private&gt;"));
});

test("includes the required WenQuanYi TrueType collection within the measured image bound", () => {
  const collection = {
    path: "truetype/wqy/wqy-zenhei.ttc",
    bytes: Buffer.from("collection fixture"),
  };
  const { entries } = readFontArchive(createFontArchive([collection]));
  assert.deepEqual(entries.get(collection.path), collection.bytes);
  // The exact pinned image contains 195 regular assets totaling 69,271,220 bytes.
  assert.ok(FONT_DATA_LIMIT > 69_271_220);
  assert.equal(FONT_DATA_LIMIT, 96 * 1024 * 1024);
});

test("font transport and export bounds cover the measured pinned archive", () => {
  assert.ok(FONT_COMPRESSED_LIMIT > 39_459_956);
  assert.equal(FONT_COMPRESSED_LIMIT, 64 * 1024 * 1024);
  const source = readFileSync(
    new URL("../ci-browser-container.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /files\.reduce\([\s\S]*?<=\s*FONT_DATA_LIMIT/);
});
