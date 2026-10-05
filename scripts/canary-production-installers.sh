#!/bin/sh
# Validate public CDN bytes and run only installer version smoke checks.
set -eu

EXPECTED_VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
BASE_URL="${QODO_SUPPORT_BUNDLE_BASE_URL:-https://get.qodo.ai/support-bundle}"
ROOT="$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl --fail --location --silent --show-error \
  --output "${work}/version.json" "${BASE_URL}/version.json"
resolved="$(
  python3 "$ROOT/scripts/version-contract.py" \
    allow-update "${work}/version.json" "$EXPECTED_VERSION"
)"
[ "$resolved" = "$EXPECTED_VERSION" ] || {
  echo "canary-production-installers: metadata selects ${resolved}, expected ${EXPECTED_VERSION}" >&2
  exit 1
}
curl --fail --location --silent --show-error \
  --output "${work}/install.sh" "${BASE_URL}/install.sh"
curl --fail --location --silent --show-error \
  --output "${work}/versioned-install.sh" \
  "${BASE_URL}/releases/${resolved}/install.sh"
cmp -s "${work}/install.sh" "${work}/versioned-install.sh"

sh "${work}/install.sh" --install-dir "${work}/metadata"
metadata_version="$("${work}/metadata/qodo-scout" version)"
[ "$metadata_version" = "$EXPECTED_VERSION" ] || {
  echo "canary-production-installers: metadata-selected binary reports ${metadata_version}, expected ${EXPECTED_VERSION}" >&2
  exit 1
}
sh "${work}/install.sh" \
  --version "$EXPECTED_VERSION" \
  --install-dir "${work}/pinned"
pinned_version="$("${work}/pinned/qodo-scout" version)"
[ "$pinned_version" = "$EXPECTED_VERSION" ] || {
  echo "canary-production-installers: pinned binary reports ${pinned_version}, expected ${EXPECTED_VERSION}" >&2
  exit 1
}
