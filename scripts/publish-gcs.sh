#!/bin/sh
# Publish an authenticated immutable release to the dev canary prefix.
set -eu

BUCKET="${QODO_SUPPORT_BUNDLE_BUCKET:-qodo-cli-public-dev}"
PREFIX="${QODO_SUPPORT_BUNDLE_PREFIX:-support-bundle}"
VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
ROOT="$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)"
DIST="${QODO_SUPPORT_BUNDLE_DIST:-$ROOT/dist}"
. "$ROOT/scripts/gcs-exact-object.sh"
. "$ROOT/scripts/release-contract.sh"

printf '%s\n' "$VERSION" |
  grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$' || {
  echo "publish-gcs: invalid version: ${VERSION}" >&2
  exit 1
}
case "$PREFIX" in
  ""|/*|*/|*..*|*[!A-Za-z0-9._/-]*)
    echo "publish-gcs: unsafe prefix '$PREFIX'" >&2
    exit 1
    ;;
esac

validate_release_directory "$DIST" publish-gcs

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT HUP INT TERM
existing="${work}/existing"
access_token="$(gcloud auth print-access-token)"

upload_immutable_release \
  "$DIST" "$BUCKET" "$PREFIX" "$VERSION" "$access_token" "$existing" publish-gcs

immutable_cache='public, max-age=31536000, immutable'
release_files | while IFS= read -r filename; do
  gcs_verify_exact \
    "${DIST}/${filename}" "$BUCKET" "${PREFIX}/releases/${VERSION}/${filename}" \
    "$(release_content_type "$filename")" "$immutable_cache" \
    "$access_token" "$existing" publish-gcs
done

echo "publish-gcs: published immutable ${VERSION} at gs://${BUCKET}/${PREFIX}/releases/${VERSION}/" >&2
