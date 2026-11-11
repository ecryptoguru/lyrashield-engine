import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";

export const FONT_ARCHIVE_LIMIT = 128 * 1024 * 1024;
export const FONT_COMPRESSED_LIMIT = 64 * 1024 * 1024;
export const FONT_DATA_LIMIT = 96 * 1024 * 1024;
export const FONT_FAMILIES = [
  "FreeSans",
  "IPAGothic",
  "Loma",
  "Unifont",
  "WenQuanYi Zen Hei",
  "Noto Color Emoji",
  "Liberation Sans",
];
export const FONT_FILE =
  /^(?:truetype|opentype|type1|X11)\/[a-zA-Z0-9_./-]+\.(?:ttf|ttc|otf|pcf\.gz|enc\.gz|pfb|afm|t1|dir|alias|scale)$/;

export function createFontArchive(files) {
  const manifest = {
    version: 1,
    files: files.map(({ path, bytes }) => ({
      path,
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    })),
  };
  const records = [
    {
      path: ".ci-font-manifest.json",
      bytes: Buffer.from(JSON.stringify(manifest)),
    },
    ...files,
  ];
  const blocks = [];
  for (const { path, bytes } of records) {
    if (Buffer.byteLength(path) > 100)
      throw new Error("Font archive path is too long");
    const header = Buffer.alloc(512);
    header.write(path);
    header.write("0000600\0", 100);
    header.write("0000000\0", 108);
    header.write("0000000\0", 116);
    header.write(bytes.length.toString(8).padStart(11, "0") + "\0", 124);
    header.write("00000000000\0", 136);
    header.fill(32, 148, 156);
    header[156] = 48;
    header.write("ustar\0", 257);
    header.write("00", 263);
    const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
    header.write(checksum.toString(8).padStart(6, "0") + "\0 ", 148);
    blocks.push(
      header,
      bytes,
      Buffer.alloc((512 - (bytes.length % 512)) % 512),
    );
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

function octal(bytes) {
  const text = bytes.toString("ascii").replace(/\0.*$/, "").trim();
  if (!/^[0-7]+$/.test(text))
    throw new Error("Invalid font archive numeric field");
  return Number.parseInt(text, 8);
}

export function readFontArchive(compressed) {
  if (!Buffer.isBuffer(compressed) || compressed.length > FONT_COMPRESSED_LIMIT)
    throw new Error("Font archive compressed size exceeds its bound");
  const archive = gunzipSync(compressed, {
    maxOutputLength: FONT_ARCHIVE_LIMIT,
  });
  const entries = new Map();
  let offset = 0;
  let total = 0;
  let ended = false;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      ended = true;
      break;
    }
    if (header[156] !== 0 && header[156] !== 48)
      throw new Error("Font archive contains a link, sparse or special entry");
    if (
      header.toString("ascii", 257, 263) !== "ustar\0" ||
      header.subarray(345, 500).some((byte) => byte !== 0)
    )
      throw new Error("Font archive format is unsupported");
    const path = header.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    if (
      (path !== ".ci-font-manifest.json" && !FONT_FILE.test(path)) ||
      path.split("/").some((part) => part === "." || part === ".." || !part)
    )
      throw new Error("Font archive path is outside the allowlist");
    if (entries.has(path) || entries.size >= 512)
      throw new Error("Duplicate or excessive font entries");
    const checksum = [...header].reduce(
      (sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte),
      0,
    );
    if (checksum !== octal(header.subarray(148, 156)))
      throw new Error("Font archive checksum mismatch");
    const size = octal(header.subarray(124, 136));
    if (size > 32 * 1024 * 1024 || (total += size) > FONT_DATA_LIMIT)
      throw new Error("Font archive data exceeds its bound");
    const next = offset + 512 + Math.ceil(size / 512) * 512;
    if (next > archive.length) throw new Error("Truncated font archive");
    entries.set(path, archive.subarray(offset + 512, offset + 512 + size));
    offset = next;
  }
  if (
    !ended ||
    archive.length % 512 ||
    archive.length - offset < 1024 ||
    archive.subarray(offset).some((byte) => byte !== 0)
  )
    throw new Error("Invalid font archive trailer");
  const manifestBytes = entries.get(".ci-font-manifest.json");
  if (!manifestBytes || manifestBytes.length > 128 * 1024)
    throw new Error("Font manifest is unavailable");
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  entries.delete(".ci-font-manifest.json");
  if (
    manifest.version !== 1 ||
    !Array.isArray(manifest.files) ||
    manifest.files.length !== entries.size ||
    !entries.size
  )
    throw new Error("Font manifest shape mismatch");
  const seen = new Set();
  for (const file of manifest.files) {
    const bytes = entries.get(file.path);
    if (
      !bytes ||
      seen.has(file.path) ||
      file.size !== bytes.length ||
      file.sha256 !== createHash("sha256").update(bytes).digest("hex")
    )
      throw new Error("Font manifest integrity mismatch");
    seen.add(file.path);
  }
  return { entries, manifest };
}

export function unpackFonts(compressed, directory) {
  const { entries, manifest } = readFontArchive(compressed);
  // Validation finishes before any archive-derived path is written.
  for (const [path, bytes] of entries) {
    const parts = path.split("/");
    mkdirSync(join(directory, ...parts.slice(0, -1)), {
      recursive: true,
      mode: 0o700,
    });
    writeFileSync(join(directory, path), bytes, { flag: "wx", mode: 0o600 });
  }
  return manifest;
}

export function fontconfigOverlay(fonts, cache) {
  const escape = (value) =>
    value
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  return `<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd"><fontconfig><cachedir>${escape(cache)}</cachedir><include ignore_missing="no">/etc/fonts/fonts.conf</include><dir>${escape(fonts)}</dir><selectfont><rejectfont><glob>*</glob></rejectfont><acceptfont><glob>${escape(fonts)}/*</glob></acceptfont></selectfont></fontconfig>\n`;
}
