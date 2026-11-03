#!/bin/sh
# GHSA-6q48-6c7w-9gw2: distrust only the compromised emSign G3 root.
set -eu
root=${1:-/}
cert="$root/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt"
config="$root/etc/ca-certificates.conf"
expected=86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fingerprint() {
    value=$(openssl x509 -in "$1" -noout -fingerprint -sha256) || return 1
    value=$(printf '%s' "$value" | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
    [ "${#value}" -eq 64 ] || return 1
    case "$value" in *[!0-9a-f]*) return 1 ;; esac
    printf '%s' "$value"
}
split_certificates() {
    [ -f "$1" ] && [ -r "$1" ] || { echo 'Missing or unreadable active CA file' >&2; return 1; }
    rm -f "$work"/*.pem
    # Parse every PEM block. Truncated, nested, empty or stray non-comment input
    # fails before fingerprints are considered; OpenSSL validates each X.509 DER.
    awk -v directory="$work" '
      { sub(/\r$/, "") }
      /^-----BEGIN CERTIFICATE-----$/ {
        if (inside) { bad=1; exit 1 }; inside=1; count++; file=directory "/" count ".pem";
        print > file; next
      }
      /^-----END CERTIFICATE-----$/ {
        if (!inside) { bad=1; exit 1 }; print > file; close(file); inside=0; next
      }
      inside { if ($0 !~ /^[A-Za-z0-9+\/=]+$/) { bad=1; exit 1 }; print > file; next }
      /^[[:space:]]*($|#)/ { next }
      { bad=1; exit 1 }
      END { if (bad || inside || !count) exit 1; print count > (directory "/count") }
    ' "$1" || { echo 'Malformed active CA file' >&2; return 1; }
}
if [ -f "$cert" ]; then
    split_certificates "$cert"
    set -- "$work"/*.pem
    [ "$#" -eq 1 ] && [ "$(fingerprint "$1")" = "$expected" ] || {
        echo 'Unreviewed emSign G3 certificate bytes' >&2; exit 1;
    }
    # Preserve packaged source and unrelated anchors; rebuild both trust paths.
    sed -i 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt$|!mozilla/emSign_ECC_Root_CA_-_G3.crt|' "$config"
fi
update-ca-certificates --fresh --certsconf "$config" \
    --certsdir "$root/usr/share/ca-certificates" \
    --localcertsdir "$root/usr/local/share/ca-certificates" \
    --etccertsdir "$root/etc/ssl/certs"
# Collect every validated block, then parse all X.509 objects together where
# OpenSSL supports -multi. Avoid a process per root under CPU emulation.
: > "$work/active.bundle"
total=0
check_active_file() {
    split_certificates "$1"
    cat "$work"/*.pem >> "$work/active.bundle"
    read -r count < "$work/count"
    total=$((total + count))
}
# Check the effective concatenated CAfile, including every certificate in it.
check_active_file "${SSL_CERT_FILE:-$root/etc/ssl/certs/ca-certificates.crt}"
# Inspect the actual lookup files, including hash-only entries and broken links.
store_paths=${SSL_CERT_DIR:-$root/etc/ssl/certs}
old_ifs=$IFS
IFS=:
for directory in $store_paths; do
    [ -d "$directory" ] || { echo 'Missing active CA directory' >&2; exit 1; }
    for active in "$directory"/*; do
        case "${active##*/}" in
            *.pem|*.crt|????????.[0-9]*) check_active_file "$active" ;;
        esac
    done
done
IFS=$old_ifs

if openssl x509 -help 2>&1 | grep -q -- '-multi[[:space:]]'; then
    openssl x509 -multi -in "$work/active.bundle" -noout -fingerprint -sha256 > "$work/raw" || {
        echo 'Malformed active X.509 certificate' >&2; exit 1;
    }
    cut -d= -f2 "$work/raw" | tr -d ':' | tr 'A-F' 'a-f' > "$work/fingerprints"
    awk -v expected="$total" '
      length($0) != 64 || $0 !~ /^[0-9a-f]+$/ { bad=1 }
      END { if (bad || NR != expected) exit 1 }
    ' "$work/fingerprints" || { echo 'Incomplete active X.509 parse' >&2; exit 1; }
    if grep -Fqx "$expected" "$work/fingerprints"; then
        echo 'Compromised emSign G3 remains trusted' >&2; exit 1
    fi
else
    split_certificates "$work/active.bundle"
    for item in "$work"/*.pem; do
        actual=$(fingerprint "$item") || { echo 'Malformed active X.509 certificate' >&2; exit 1; }
        [ "$actual" != "$expected" ] || { echo 'Compromised emSign G3 remains trusted' >&2; exit 1; }
    done
fi
