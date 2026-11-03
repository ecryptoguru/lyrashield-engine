#!/bin/sh
# Rebuild signed distro payloads using the pinned compiler from the preceding layer.
set -eu
inputs=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output=${1:-/out/distro}
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
arch=$(dpkg --print-architecture)
case "$arch" in amd64|arm64) ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac
[ "$(go env GOVERSION)" = go1.27.3 ]
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
export GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
export GOMEMLIMIT=${GOMEMLIMIT:-1200MiB} GOGC=${GOGC:-50} GOMAXPROCS=${GOMAXPROCS:-1}
# Fixed archive timestamp avoids embedding the wall clock in the local .debs.
export SOURCE_DATE_EPOCH=1791569838

fetch() {
    curl -fsSL --retry 5 --retry-delay 2 --retry-max-time 120 "$pool/$1" -o "$1"
    printf '%s  %s\n' "$2" "$1" | sha256sum -c -
}

while IFS='|' read -r name version dsc orig overlay armdeb amddeb; do
    case "$name" in ''|'#'*) continue ;; esac
    pool="https://kali.download/kali/pool/main/${name%"${name#?}"}/$name"
    mkdir "$work/$name"
    cd "$work/$name"
    upstream=${version%-*}
    fetch "${name}_${version}.dsc" "$dsc"
    fetch "${name}_${upstream}.orig.tar.gz" "$orig"
    fetch "${name}_${version}.debian.tar.xz" "$overlay"
    case "$arch" in arm64) deb=$armdeb ;; amd64) deb=$amddeb ;; esac
    fetch "${name}_${version}_${arch}.deb" "$deb"
    mkdir src
    tar -xzf "${name}_${upstream}.orig.tar.gz" --strip-components=1 -C src
    tar -xJf "${name}_${version}.debian.tar.xz" -C src
    dpkg-deb -R "${name}_${version}_${arch}.deb" package
    cd src
    if [ -f debian/patches/series ]; then
        while read -r patchname; do
            case "$patchname" in ''|'#'*) continue ;; esac
            patch --batch --fuzz=0 -p1 < "debian/patches/$patchname"
        done < debian/patches/series
    fi
    if [ -f "$inputs/$name/source.patch" ]; then
        patch --batch --fuzz=0 -p1 < "$inputs/$name/source.patch"
    fi
    cp "$inputs/$name/go.mod" "$inputs/$name/go.sum" .
    sha256sum go.mod go.sum > ../graph.sha256
    target="cmd/$name/main.go"
    export CGO_ENABLED=1
    flags='-s -w'
    case "$name" in
        ffuf) target=. ;;
        nuclei) CGO_ENABLED=0; flags='-s -w -extldflags=-static' ;;
    esac
    go mod download
    go mod verify
    go build -p 1 -mod=readonly -buildvcs=false -trimpath -pgo=auto \
        -ldflags "$flags" -o "../package/usr/bin/$name" "$target"
    if [ "$name" = nuclei ]; then
        go list -mod=readonly -deps "$target" > ../nuclei-deps.txt
        if grep -Eq '^golang.org/x/crypto/openpgp(/|$)' ../nuclei-deps.txt; then
            echo "Nuclei links the deprecated OpenPGP implementation" >&2
            exit 1
        fi
        go test -count=1 -trimpath -p 1 -mod=readonly "$inputs/nuclei/sdk_test.go"
        cp "$inputs/nuclei/testdata/template_adapter_test.go" pkg/external/customtemplates/
        cp "$inputs/nuclei/testdata/tracker_adapter_test.go" pkg/reporting/trackers/github/
        go test -count=1 -trimpath -p 1 -mod=readonly -run '^TestLyra' \
            ./pkg/external/customtemplates ./pkg/reporting/trackers/github
    fi
    provenance="../package/usr/share/doc/$name/lyrashield-build"
    mkdir -p "$provenance"
    cp go.mod go.sum ../graph.sha256 "$inputs/sources.tsv" "$provenance/"
    cp "../${name}_${version}.dsc" "$provenance/"
    cp "$inputs/README.md" "$provenance/"
    if [ -f "$inputs/$name/source.patch" ]; then
        cp "$inputs/$name/source.patch" "$provenance/"
    fi
    cp "$(go env GOROOT)/LICENSE" "$provenance/Go-LICENSE"
    cp "$(go env GOROOT)/PATENTS" "$provenance/Go-PATENTS"
    for notice in LICENSE LICENSE.txt LICENSE.md COPYING NOTICE NOTICE.txt NOTICE.md; do
        if [ -f "$notice" ]; then cp "$notice" "$provenance/"; fi
    done
    go list -mod=readonly -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}|{{.Dir}}{{end}}{{end}}' "$target" > ../dependency-paths
    sort -u ../dependency-paths > ../unique-dependencies
    while IFS='|' read -r module module_dir; do
        [ -n "$module" ] || continue
        for notice in "$module_dir"/LICENSE* "$module_dir"/COPYING* "$module_dir"/NOTICE* "$module_dir"/PATENTS*; do
            [ -f "$notice" ] || continue
            mkdir -p "$provenance/third-party/$module"
            cp "$notice" "$provenance/third-party/$module/"
        done
    done < ../unique-dependencies
    sha256sum -c ../graph.sha256
    go version -m "../package/usr/bin/$name" > "$provenance/buildinfo.txt"
    cd ../package
    sha256sum "usr/bin/$name" > "usr/share/doc/$name/lyrashield-build/binary.sha256"
    # Replace obsolete compiler/source claims from the original binary packaging.
    # amd64/arm64 are built natively against the builder's pinned-suite glibc.
    awk -v v="$version+lyra1" -v tool="$name" '
        /^(Built-Using|Static-Built-Using):/ {skip=1; next}
        /^[ \t]/ && skip {next}
        {skip=0}
        /^Version:/ {print "Version: " v; next}
        /^Depends:/ && tool=="naabu" {print $0 ", libpcap0.8t64"; next}
        /^Installed-Size:/ {next}
        {print}
    ' DEBIAN/control > ../control
    printf 'Installed-Size: %s\n' "$(du -sk --apparent-size --exclude=DEBIAN . | cut -f1)" >> ../control
    mv ../control DEBIAN/control
    find . -path ./DEBIAN -prune -o -type f -print0 | sort -z | \
        xargs -0 md5sum | sed 's@  \./@  @' > DEBIAN/md5sums
    dpkg-deb --root-owner-group --threads-max=1 -Zxz -z3 --build . \
        "$output/${name}_${version}+lyra1_${arch}.deb"
    cd "$work"
    rm -rf "$work/$name"
done < "$inputs/sources.tsv"
