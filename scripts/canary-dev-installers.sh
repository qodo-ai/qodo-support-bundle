#!/bin/sh
# Exercise pinned and metadata-selected installers against exact dev objects.
set -eu

BUCKET="${QODO_SUPPORT_BUNDLE_BUCKET:-qodo-cli-public-dev}"
PREFIX="${QODO_SUPPORT_BUNDLE_PREFIX:-support-bundle}"
EXPECTED_VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
ROOT="$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
release="${work}/release"
mkdir "$release"

gcloud storage cp "gs://${BUCKET}/${PREFIX}/version.json" "${work}/version.json"
resolved="$(
  python3 "$ROOT/scripts/version-contract.py" \
    allow-update "${work}/version.json" "$EXPECTED_VERSION"
)"
[ "$resolved" = "$EXPECTED_VERSION" ] || {
  echo "canary-dev-installers: dev metadata selects ${resolved}, expected ${EXPECTED_VERSION}" >&2
  exit 1
}

for filename in \
  install.sh \
  checksums.sha256 \
  qodo-support-bundle-linux-amd64
do
  gcloud storage cp \
    "gs://${BUCKET}/${PREFIX}/releases/${resolved}/${filename}" \
    "${release}/${filename}"
done
gcloud storage cp "gs://${BUCKET}/${PREFIX}/install.sh" "${work}/install.sh"
cmp -s "${work}/install.sh" "${release}/install.sh" || {
  echo "canary-dev-installers: stable and versioned Unix installers differ" >&2
  exit 1
}

sh "${work}/install.sh" \
  --version "$EXPECTED_VERSION" \
  --source-dir "$release" \
  --install-dir "${work}/pinned"
"${work}/pinned/qodo-scout" version

sh "${work}/install.sh" \
  --version "$resolved" \
  --source-dir "$release" \
  --install-dir "${work}/metadata"
"${work}/metadata/qodo-scout" version
