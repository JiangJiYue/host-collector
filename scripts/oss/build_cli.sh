#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="${1:-"${ROOT_DIR}/dist/oss-cli"}"
GOCACHE_DIR="${GOCACHE:-"${TMPDIR:-/tmp}/host-collector-go-cache"}"

mkdir -p "${DIST_DIR}" "${GOCACHE_DIR}"

build_go() {
  local module_dir="$1"
  local goos="$2"
  local goarch="$3"
  local output="$4"
  local package_path="$5"

  (
    cd "${ROOT_DIR}/${module_dir}"
    env GOCACHE="${GOCACHE_DIR}" GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 \
      go build -trimpath -o "${DIST_DIR}/${output}" "${package_path}"
  )
}

build_go "windows-host-collector" "windows" "amd64" "host-collector-windows10-cli.exe" "./cmd/headless-collector"
build_go "windows-host-collector" "windows" "amd64" "host-collector-windows7-cli.exe" "./cmd/headless-collector"
build_go "linux-host-collector" "linux" "amd64" "host-collector-linux-amd64" "./cmd/linux-host-collector"
build_go "linux-host-collector" "linux" "arm64" "host-collector-linux-arm64" "./cmd/linux-host-collector"

printf 'OSS CLI artifacts written to %s\n' "${DIST_DIR}"
