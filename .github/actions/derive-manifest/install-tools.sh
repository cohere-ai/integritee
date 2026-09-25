#!/usr/bin/env bash
set -euo pipefail

readonly KUSTOMIZE_VERSION="5.8.1"
readonly KUSTOMIZE_SHA256="029a7f0f4e1932c52a0476cf02a0fd855c0bb85694b82c338fc648dcb53a819d"
readonly TOOLS_DIR="${RUNNER_TEMP:?RUNNER_TEMP must be set}/integritee-policy-tools"
readonly BIN_DIR="${TOOLS_DIR}/bin"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "ERROR: policy derivation currently supports Linux x86_64 runners only" >&2
  exit 1
fi

mkdir -p "${BIN_DIR}"

KUSTOMIZE_ARCHIVE="${TOOLS_DIR}/kustomize.tar.gz"
curl --fail --silent --show-error --location \
  "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v${KUSTOMIZE_VERSION}/kustomize_v${KUSTOMIZE_VERSION}_linux_amd64.tar.gz" \
  --output "${KUSTOMIZE_ARCHIVE}"
printf '%s  %s\n' "${KUSTOMIZE_SHA256}" "${KUSTOMIZE_ARCHIVE}" | sha256sum --check --status
tar -xzf "${KUSTOMIZE_ARCHIVE}" -C "${BIN_DIR}" kustomize

echo "${BIN_DIR}" >> "${GITHUB_PATH:?GITHUB_PATH must be set}"
"${BIN_DIR}/kustomize" version
