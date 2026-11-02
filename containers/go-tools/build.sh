#!/bin/sh
# Rebuild immutable upstream sources with the reviewed, checksum-verified graph.
set -eu
inputs="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
output="${1:-/out/bin}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT HUP INT TERM
metadata="${output%/bin}/share/go-tools"
mkdir -p "$output" "$metadata"
cp "$inputs/sources.tsv" "$metadata/sources.tsv"
cp "$inputs/README.md" "$metadata/README.md"
cp "$inputs/verify_goldmark.go" "$metadata/verify_goldmark.go"
export CGO_ENABLED=0 GOTOOLCHAIN=local GOSUMDB=sum.golang.org
# Bound generated cloud SDK compiler heaps without changing build semantics.
export GOMEMLIMIT="${GOMEMLIMIT:-1200MiB}" GOGC="${GOGC:-50}" GOMAXPROCS="${GOMAXPROCS:-1}"
export GOPROXY=https://proxy.golang.org
[ "$(go env GOVERSION)" = go1.27.3 ]
for notice in LICENSE PATENTS; do
    if [ -f "$(go env GOROOT)/$notice" ]; then
        cp "$(go env GOROOT)/$notice" "$metadata/Go-$notice"
    fi
done
while IFS='|' read -r name repository commit checksum package tags experiment version; do
    case "$name" in ''|'#'*) continue ;; esac
    source="$work/$name"
    mkdir -p "$source"
    curl --retry 5 --retry-delay 2 --retry-max-time 120 -fsSL \
        "https://codeload.github.com/$repository/tar.gz/$commit" -o "$work/source.tgz"
    echo "$checksum  $work/source.tgz" | sha256sum -c -
    tar -xzf "$work/source.tgz" --strip-components=1 -C "$source"
    cp "$inputs/$name/go.mod" "$inputs/$name/go.sum" "$source/"
    (
        cd "$source"
        sha256sum go.mod go.sum > "$work/graph.sha256"
        if [ -f "$inputs/$name/source.patch" ]; then
            patch --batch --fuzz=0 -p1 < "$inputs/$name/source.patch"
        fi
        go mod download
        go mod verify
        # Never silently resolve a newer graph while compiling a release.
        flags='-s -w -extldflags=-static'
        if [ -n "$version" ]; then flags="$flags -X $version"; fi
        GOEXPERIMENT="$experiment" go build -p 1 -mod=readonly -trimpath \
            -tags "$tags" -ldflags "$flags" -o "$output/$name" "$package"
        go version -m "$output/$name" > "$work/buildinfo.txt"
        if grep -Eq '^[[:space:]]+dep[[:space:]]+github.com/yuin/goldmark[[:space:]]' "$work/buildinfo.txt"; then
            go run -p 1 -mod=readonly -trimpath "$inputs/verify_goldmark.go"
        fi
        sha256sum -c "$work/graph.sha256"
        provenance="$metadata/$name"
        mkdir -p "$provenance"
        cp go.mod go.sum "$provenance/"
        cp "$work/graph.sha256" "$provenance/modules.sha256"
        (cd "$output" && sha256sum "$name") > "$provenance/binary.sha256"
        if [ -f "$inputs/$name/source.patch" ]; then
            cp "$inputs/$name/source.patch" "$provenance/source.patch"
            (cd "$provenance" && sha256sum source.patch) > "$provenance/source.patch.sha256"
        fi
        for license in LICENSE LICENSE.txt LICENSE.md COPYING NOTICE NOTICE.txt NOTICE.md; do
            if [ -f "$license" ]; then cp "$license" "$provenance/"; fi
        done
        printf 'https://codeload.github.com/%s/tar.gz/%s\nSHA256 %s\n' \
            "$repository" "$commit" "$checksum" > "$provenance/source.txt"
        cp "$work/buildinfo.txt" "$provenance/buildinfo.txt"
        cat "$provenance/buildinfo.txt"
    )
    rm -rf "$source" "$work/source.tgz"
done < "$inputs/sources.tsv"
