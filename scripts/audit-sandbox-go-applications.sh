#!/usr/bin/env bash
# Supplement binary scans with accurate, byte-bound application coordinates.
set -euo pipefail
image=${1:?usage: audit-sandbox-go-applications.sh <image> [platform]}
platform=${2:-linux/amd64}
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
audit_dir=$(mktemp -d)
trap 'rm -rf "$audit_dir"' EXIT
cp "$repo_root/containers/verify_go_tool_provenance.py" "$audit_dir/verify_go_tool_provenance.py"
cp "$repo_root/containers/go-tools/distro/verify.py" "$audit_dir/verify_distro_go_tools.py"
cp "$repo_root/containers/go-tools/applications.json" "$audit_dir/expected-applications.json"
cp "$repo_root/containers/go-tools/distro/applications.cdx.json" "$audit_dir/expected-distro.cdx.json"
# Both inventories are mandatory. Validate final installed bytes against builder
# receipts before exporting any application coordinates to the scanner.
docker run --rm --platform "$platform" --network none \
  --volume "$audit_dir:/audit:ro" --entrypoint /app/.venv/bin/python "$image" \
  /audit/verify_go_tool_provenance.py \
  --manifest /audit/expected-applications.json --emit-verified-sbom > "$audit_dir/applications.cdx.json"
docker run --rm --platform "$platform" --network none \
  --volume "$audit_dir:/audit:ro" --entrypoint /app/.venv/bin/python "$image" \
  /audit/verify_distro_go_tools.py --receipts-only
docker run --rm --platform "$platform" --network none \
  --volume "$audit_dir:/audit:ro" --entrypoint /app/.venv/bin/python "$image" -c '
import json
from pathlib import Path
expected=json.loads(Path("/audit/expected-distro.cdx.json").read_text())
actual=json.loads(Path("/usr/local/share/lyrashield/go-tools/distro/applications.cdx.json").read_text())
if actual != expected or len(actual.get("components", [])) != 4:
    raise SystemExit("distro application coordinates missing or changed")
print(json.dumps(actual))
' > "$audit_dir/distro-applications.cdx.json"
# Independent negative control: a historical main-application advisory must
# match. This is a test inventory, never the inventory of the current image.
cat > "$audit_dir/main-module-canary.cdx.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"application","bom-ref":"main-module-canary","name":"github.com/projectdiscovery/interactsh","version":"v1.1.9","purl":"pkg:golang/github.com/projectdiscovery/interactsh@v1.1.9"}]}
JSON
scan() {
  docker run --rm --platform "$platform" --user "$(id -u):$(id -g)" -e HOME=/tmp \
    --volume "$audit_dir:/audit" \
    --entrypoint /usr/local/bin/trivy "$image" sbom \
    --cache-dir /audit/trivy-cache --scanners vuln --severity HIGH,CRITICAL --exit-code 1 \
    --format json --output "/audit/$2" "/audit/$1"
}
canary_exit=0
scan main-module-canary.cdx.json canary-report.json || canary_exit=$?
if [ "$canary_exit" -ne 1 ]; then
  echo "Main-module advisory negative control did not fail as expected" >&2; exit 1
fi
python3 - "$audit_dir/canary-report.json" <<'PY'
import json,sys
report=json.load(open(sys.argv[1]))
if not any(v.get("VulnerabilityID")=="CVE-2024-5262" and
           v.get("PkgName")=="github.com/projectdiscovery/interactsh" and
           v.get("InstalledVersion")=="v1.1.9"
           for r in report.get("Results",[]) for v in r.get("Vulnerabilities",[])):
    raise SystemExit("Expected main-module advisory missing from scanner output")
PY
scan applications.cdx.json applications-report.json
scan distro-applications.cdx.json distro-applications-report.json
