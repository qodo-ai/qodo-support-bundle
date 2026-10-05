#!/bin/sh
# Exercise a pinned installer against exact versioned dev objects.
set -eu

BUCKET="${QODO_SUPPORT_BUNDLE_BUCKET:-qodo-cli-public-dev}"
PREFIX="${QODO_SUPPORT_BUNDLE_PREFIX:-support-bundle}"
export QODO_SUPPORT_BUNDLE_BUCKET="$BUCKET"
export QODO_SUPPORT_BUNDLE_PREFIX="$PREFIX"
EXPECTED_VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
release="${work}/release"
mkdir "$release"

for filename in \
  install.sh \
  checksums.sha256 \
  qodo-support-bundle-linux-amd64
do
  gcloud storage cp \
    "gs://${BUCKET}/${PREFIX}/releases/${EXPECTED_VERSION}/${filename}" \
    "${release}/${filename}"
done

sh "${release}/install.sh" \
  --version "$EXPECTED_VERSION" \
  --source-dir "$release" \
  --install-dir "${work}/pinned"
pinned_version="$("${work}/pinned/qodo-scout" version)"
[ "$pinned_version" = "$EXPECTED_VERSION" ] || {
  echo "canary-dev-installers: pinned binary reports ${pinned_version}, expected ${EXPECTED_VERSION}" >&2
  exit 1
}
