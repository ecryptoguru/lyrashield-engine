#!/bin/sh
# GHSA-6q48-6c7w-9gw2: distrust only the compromised emSign G3 root.
# Run before the first HTTPS download and again after package installation.
set -eu
root=${1:-/}
cert="$root/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt"
config="$root/etc/ca-certificates.conf"
expected=86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b
if [ -f "$cert" ]; then
    actual=$(openssl x509 -in "$cert" -outform DER | sha256sum | cut -d ' ' -f 1)
    [ "$actual" = "$expected" ] || { echo 'Unreviewed emSign G3 certificate bytes' >&2; exit 1; }
    # Keep the packaged source and all other trust anchors. update-ca-certificates
    # removes this root from both the bundle and the hashed CA directory.
    sed -i 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt$|!mozilla/emSign_ECC_Root_CA_-_G3.crt|' "$config"
fi
update-ca-certificates --fresh --certsconf "$config" \
    --certsdir "$root/usr/share/ca-certificates" \
    --localcertsdir "$root/usr/local/share/ca-certificates" \
    --etccertsdir "$root/etc/ssl/certs"
# Inspect every active anchor, including local additions and symlink targets.
for active in "$root"/etc/ssl/certs/*.pem; do
    [ -f "$active" ] || continue
    actual=$(openssl x509 -in "$active" -outform DER | sha256sum | cut -d ' ' -f 1)
    [ "$actual" != "$expected" ] || { echo 'Compromised emSign G3 remains trusted' >&2; exit 1; }
done
