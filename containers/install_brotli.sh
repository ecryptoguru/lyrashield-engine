#!/bin/sh
# Debian's CVE-2026-111497 backport. Both runtime decoders need the fix:
# Python's _brotli extension statically bundles Brotli and does not use libbrotli1.
set -eu
version=1.2.0-4.1
arch=$(dpkg --print-architecture)
case "$arch" in
    amd64)
        lib_checksum=2d58db32250aa535e27c62e98451debd43b539aa026066806432e842d5b56c00
        python_checksum=3b62003bf956337d2ae672b40174cd303e740ea0e013d8405e503a4b5abaf061 ;;
    arm64)
        lib_checksum=ff90055f0c42dc39fdf8f12d7f68c7da32da2ec90d0a49eb39e80b764988ee02
        python_checksum=0923c03d9293e45cd8f744f1de5103b97603f0ae0c54b275d8f03ebf87b29750 ;;
    *) printf 'Unsupported Brotli decoder architecture: %s\n' "$arch" >&2; exit 1 ;;
esac
directory=$(mktemp -d /tmp/lyrashield-brotli.XXXXXX)
trap 'rm -rf "$directory"' EXIT HUP INT TERM
for name in libbrotli1 python3-brotli; do
    installed=$(dpkg-query -W -f='${Version}' "$name" 2>/dev/null || true)
    if [ -n "$installed" ] && dpkg --compare-versions "$installed" ge "$version"; then
        printf 'Brotli decoder already fixed: %s %s\n' "$name" "$installed"
        continue
    fi
    case "$name" in libbrotli1) checksum=$lib_checksum ;; python3-brotli) checksum=$python_checksum ;; esac
    package="$directory/${name}_${version}_${arch}.deb"
    curl --retry 5 --retry-delay 2 --retry-max-time 120 -fsSL \
        "https://deb.debian.org/debian/pool/main/b/brotli/${name}_${version}_${arch}.deb" \
        -o "$package"
    printf '%s  %s\n' "$checksum" "$package" | sha256sum -c -
done
# Check every downloaded package before installing any of them.
set -- "$directory"/*.deb
if [ -f "$1" ]; then dpkg --install "$@"; fi
for name in libbrotli1 python3-brotli; do
    installed=$(dpkg-query -W -f='${Version}' "$name")
    source_version=$(dpkg-query -W -f='${source:Version}' "$name")
    dpkg --compare-versions "$installed" ge "$version"
    dpkg --compare-versions "$source_version" ge "$version"
    printf 'Verified Brotli decoder: %s %s source=%s (%s)\n' "$name" "$installed" "$source_version" "$arch"
done
