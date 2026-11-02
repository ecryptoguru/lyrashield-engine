// Narrow downstream source amendment to the exact hash-locked Retire 6.1.0.
// Node must verify the requested IP while omitting IP SNI on CONNECT tunnels.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
function patch(root) {
  const file = path.join(root, "retire/lib/http.js");
  const metadata = JSON.parse(fs.readFileSync(path.join(root, "retire/package.json"), "utf8"));
  const data = fs.readFileSync(file);
  if (metadata.version !== "6.1.0" || crypto.createHash("sha256").update(data).digest("hex") !==
      "b4ecf44ccfa66565b126b725e3e801b13223d12eb7b63298749b58edbb420796") {
    throw new Error("Unreviewed Retire TLS source; refusing amendment");
  }
  const original = "tls.connect({ ...tlsSettings, socket, servername })";
  const corrected = "tls.connect({ ...tlsSettings, socket, host: unbracket(target.hostname), servername })";
  const source = data.toString("utf8");
  if (source.split(original).length !== 2) throw new Error("Unexpected Retire TLS call");
  fs.writeFileSync(file, source.replace(original, corrected));
}
if (require.main === module) patch(process.argv[2]);
module.exports = {patch};
