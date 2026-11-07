#!/usr/bin/env bash
# Exact corresponding-source build. Network is needed for the pinned Go toolchain
# (go.dev) and go.sum-verified modules (proxy.golang.org only; no direct VCS/GitHub fallback).
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
SBOX_BUILD_ROOT="$PWD"
SBOX_CORE_CACHE="${SBOX_CORE_BUILD_CACHE:-$SBOX_BUILD_ROOT/.cache}"
mkdir -p "$SBOX_CORE_CACHE"
if [ ! -x "$SBOX_CORE_CACHE/go/bin/go" ];then
 curl -fL --retry 3 https://go.dev/dl/go1.27.3.linux-amd64.tar.gz -o "$SBOX_CORE_CACHE/go.tar.gz"
 printf '%s  %s\n' 65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 "$SBOX_CORE_CACHE/go.tar.gz" | sha256sum -c -
 tar xzf "$SBOX_CORE_CACHE/go.tar.gz" -C "$SBOX_CORE_CACHE"
fi
export PATH="$SBOX_CORE_CACHE/go/bin:$PATH" GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOMAXPROCS=4
export GONOSUMDB='' GOPRIVATE='' GONOPROXY='' GOINSECURE='' GOENV=off
export GOPATH="$SBOX_CORE_CACHE/gopath" GOCACHE="$SBOX_CORE_CACHE/gocache" GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOFLAGS=-mod=readonly
[ "$(go version)" = 'go version go1.27.3 linux/amd64' ] || { echo 'Expected pinned Go 1.27.3 linux/amd64; use a clean SBOX_CORE_BUILD_CACHE.' >&2; exit 1; }
cd sing-box
printf '%s  %s\n' 69d1da41564198b378cccdd86c29bbdf6dca4887e987d84af14108c8555c2c1b go.sum | sha256sum -c -
go list -deps -tags "$(cat release/DEFAULT_BUILD_TAGS),with_purego,with_v2ray_api,with_sbox_accounting" ./cmd/sing-box >/dev/null
go mod verify
SBOX_TAGS="$(cat release/DEFAULT_BUILD_TAGS),with_purego,with_v2ray_api,with_sbox_accounting"
SBOX_LDFLAGS="$(cat release/LDFLAGS) -X github.com/sagernet/sing-box/constant.Version=1.14.4 -s -w -buildid="
go test -p 4 -tags "$SBOX_TAGS" -ldflags "$SBOX_LDFLAGS" ./experimental/v2rayapi
go build -p 4 -trimpath -buildvcs=false -tags "$SBOX_TAGS" -ldflags "$SBOX_LDFLAGS" -o ../sing-box-accounting ./cmd/sing-box
cd ..
printf '%s  %s\n' e3faddd1000494fb8607984f85ec2cdfd5d01033c71d2b0e8bc63aa6a2b2d184 sing-box-accounting | sha256sum -c -
