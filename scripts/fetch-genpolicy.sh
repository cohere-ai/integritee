#!/usr/bin/env bash
# Fetch the genpolicy binary from Kata Containers releases.
#
# Usage:
#   ./fetch-genpolicy.sh [--version 3.12.0] [--output /usr/local/bin/genpolicy]
#
# Distribution options:
#   1. GitHub Release tarball (preferred):
#      https://github.com/kata-containers/kata-containers/releases/download/{tag}/
#      The genpolicy binary is bundled in the kata-static tarball.
#
#   2. kata-deploy container image (alternative):
#      ghcr.io/kata-containers/kata-deploy:{tag}
#      Binary at /opt/kata/bin/genpolicy inside the image.
#
# This script uses option 1 (GitHub Release tarball).

set -euo pipefail

KATA_VERSION="${KATA_VERSION:-3.12.0}"
OUTPUT="${OUTPUT:-./genpolicy}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) KATA_VERSION="$2"; shift 2 ;;
    --output)  OUTPUT="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

ARCH="amd64"
# Kata packages genpolicy in two forms:
#   1. kata-tools-static-{TAG}-{ARCH}.tar.zst  (newer releases >=3.13, smaller, tools only)
#   2. kata-static-{TAG}-{ARCH}.tar.xz         (older releases, full bundle)
# Binary path inside both: opt/kata/bin/genpolicy

TOOLS_URL="https://github.com/kata-containers/kata-containers/releases/download/${KATA_VERSION}/kata-tools-static-${KATA_VERSION}-${ARCH}.tar.zst"
STATIC_URL="https://github.com/kata-containers/kata-containers/releases/download/${KATA_VERSION}/kata-static-${KATA_VERSION}-${ARCH}.tar.xz"

echo "Fetching genpolicy from Kata release ${KATA_VERSION}..." >&2

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

if curl -fSL "$TOOLS_URL" -o "${TMPDIR}/kata-tools.tar.zst" 2>/dev/null; then
  echo "Using kata-tools-static tarball (.tar.zst)" >&2
  tar --zstd -xf "${TMPDIR}/kata-tools.tar.zst" -C "${TMPDIR}" opt/kata/bin/genpolicy
elif curl -fSL "$STATIC_URL" -o "${TMPDIR}/kata-static.tar.xz" 2>/dev/null; then
  echo "Using kata-static tarball (.tar.xz)" >&2
  tar -xf "${TMPDIR}/kata-static.tar.xz" -C "${TMPDIR}" opt/kata/bin/genpolicy
else
  echo "ERROR: Could not download genpolicy from Kata release ${KATA_VERSION}" >&2
  echo "  Tried: $TOOLS_URL" >&2
  echo "  Tried: $STATIC_URL" >&2
  exit 1
fi

FOUND="${TMPDIR}/opt/kata/bin/genpolicy"
if [[ ! -f "$FOUND" ]]; then
  echo "ERROR: genpolicy binary not found after extraction" >&2
  exit 1
fi

cp "$FOUND" "$OUTPUT"
chmod +x "$OUTPUT"

echo "Installed genpolicy ${KATA_VERSION} -> ${OUTPUT}" >&2
"$OUTPUT" --version 2>/dev/null || echo "(version check not supported)" >&2
