import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  createFontArchive,
  FONT_FILE,
  FONT_FAMILIES,
  FONT_DATA_LIMIT,
} from "./fonts.mjs";

const packages = [
  "xvfb",
  "fonts-noto-color-emoji",
  "fonts-unifont",
  "libfontconfig1",
  "libfreetype6",
  "xfonts-cyrillic",
  "xfonts-scalable",
  "fonts-liberation",
  "fonts-ipafont-gothic",
  "fonts-wqy-zenhei",
  "fonts-tlwg-loma-otf",
  "fonts-freefont-ttf",
  "libasound2",
  "libatk-bridge2.0-0",
  "libatk1.0-0",
  "libatspi2.0-0",
  "libcairo2",
  "libcups2",
  "libdbus-1-3",
  "libdrm2",
  "libgbm1",
  "libglib2.0-0",
  "libnspr4",
  "libnss3",
  "libpango-1.0-0",
  "libwayland-client0",
  "libx11-6",
  "libxcb1",
  "libxcomposite1",
  "libxdamage1",
  "libxext6",
  "libxfixes3",
  "libxkbcommon0",
  "libxrandr2",
  "xfonts-encodings",
  "xfonts-utils",
];

function run(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    timeout: 120_000,
    maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, `${command} preflight failed`);
  return result.stdout;
}

function verifyFonts() {
  for (const name of packages.filter(
    (name) =>
      name.startsWith("fonts-") ||
      name.startsWith("xfonts-") ||
      name === "libfontconfig1",
  )) {
    assert.equal(
      run("dpkg-query", ["-W", "-f=${Status}", name]),
      "install ok installed",
      `${name} is unavailable in the pinned source image`,
    );
    const changed = run("dpkg", ["-V", name])
      .split("\n")
      .filter(
        (line) => line && !/^missing\s+\/usr\/share\/(doc|man)\//.test(line),
      );
    assert.deepEqual(changed, [], `${name} font file integrity mismatch`);
  }
  for (const family of FONT_FAMILIES)
    assert.ok(
      run("fc-match", ["-f", "%{family}\t%{file}", family]).includes(family),
      `${family} is unavailable in the source image`,
    );
}

function fontFiles(directory = "/usr/share/fonts", prefix = "") {
  return readdirSync(directory).flatMap((name) => {
    const file = join(directory, name);
    const path = prefix ? `${prefix}/${name}` : name;
    const stat = lstatSync(file);
    // Alternative aliases may be links; export only the regular font bytes.
    if (stat.isSymbolicLink()) return [];
    if (stat.isDirectory()) return fontFiles(file, path);
    if (!FONT_FILE.test(path)) return [];
    assert.ok(stat.isFile() && stat.size <= 32 * 1024 * 1024);
    return [{ path, bytes: readFileSync(file) }];
  });
}

try {
  assert.equal(process.getuid(), 1000);
  assert.match(readFileSync("/proc/self/status", "utf8"), /^CapEff:\s+0+$/m);
  assert.match(readFileSync("/proc/self/status", "utf8"), /^NoNewPrivs:\s+1$/m);
  assert.equal(process.arch, "x64");
  const command = process.argv[2];
  if (command === "verify") {
    verifyFonts();
    console.log("Pinned source font integrity and families verified");
  } else if (command === "font-archive") {
    verifyFonts();
    const files = fontFiles();
    assert.ok(
      files.length > 0 &&
        files.length < 512 &&
        files.reduce((sum, file) => sum + file.bytes.length, 0) <=
          64 * 1024 * 1024,
    );
    process.stdout.write(createFontArchive(files));
  } else throw new Error("Unknown container verification command");
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
