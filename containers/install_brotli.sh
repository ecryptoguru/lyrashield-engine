#!/bin/sh
# Debian's CVE-2026-111497 backport; package digests verified from official assets.
set -eu
version=1.2.0-4.1
installed=$(dpkg-query -W -f='${Version}' libbrotli1 2>/dev/null || true)
if [ -n "$installed" ] && dpkg --compare-versions "$installed" ge "$version"; then
    printf 'Brotli decoder already fixed: %s\n' "$installed"
    exit 0
fi
arch=$(dpkg --print-architecture)
case "$arch" in
    amd64) checksum=2d58db32250aa535e27c62e98451debd43b539aa026066806432e842d5b56c00 ;;
    arm64) checksum=ff90055f0c42dc39fdf8f12d7f68c7da32da2ec90d0a49eb39e80b764988ee02 ;;
    *) printf 'Unsupported Brotli decoder architecture: %s\n' "$arch" >&2; exit 1 ;;
esac
package=$(mktemp /tmp/lyrashield-brotli.XXXXXX.deb)
trap 'rm -f "$package"' EXIT HUP INT TERM
curl --retry 5 --retry-delay 2 --retry-max-time 120 -fsSL \
    "https://deb.debian.org/debian/pool/main/b/brotli/libbrotli1_${version}_${arch}.deb" \
    -o "$package"
printf '%s  %s\n' "$checksum" "$package" | sha256sum -c -
dpkg --install "$package"
installed=$(dpkg-query -W -f='${Version}' libbrotli1)
dpkg --compare-versions "$installed" ge "$version"
printf 'Verified Brotli decoder: %s (%s)\n' "$installed" "$arch"
