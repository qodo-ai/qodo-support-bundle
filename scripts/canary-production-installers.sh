#!/bin/sh
# Validate public CDN bytes and run only installer version smoke checks.
set -eu

EXPECTED_VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
BASE_URL="${QODO_SUPPORT_BUNDLE_BASE_URL:-https://get.qodo.ai/support-bundle}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl --fail --location --silent --show-error \
  --output "${work}/install.sh" \
  "${BASE_URL}/releases/${EXPECTED_VERSION}/install.sh"
sh "${work}/install.sh" \
  --version "$EXPECTED_VERSION" \
  --install-dir "${work}/pinned"
pinned_version="$("${work}/pinned/qodo-scout" version)"
[ "$pinned_version" = "$EXPECTED_VERSION" ] || {
  echo "canary-production-installers: pinned binary reports ${pinned_version}, expected ${EXPECTED_VERSION}" >&2
  exit 1
}
