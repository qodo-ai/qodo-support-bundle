#!/bin/sh
# Promote byte-identical immutable dev-canary assets to production.
set -eu

SOURCE_BUCKET="${QODO_SUPPORT_BUNDLE_SOURCE_BUCKET:-qodo-cli-public-dev}"
DESTINATION_BUCKET="${QODO_SUPPORT_BUNDLE_DESTINATION_BUCKET:-qodo-cli-public}"
PREFIX="${QODO_SUPPORT_BUNDLE_PREFIX:-support-bundle}"
VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
RELEASE_DIR="${QODO_SUPPORT_BUNDLE_RELEASE_DIR:?QODO_SUPPORT_BUNDLE_RELEASE_DIR is required}"
ROOT="$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/gcs-exact-object.sh"
. "$ROOT/scripts/release-contract.sh"

printf '%s\n' "$VERSION" |
  grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$' || {
  echo "promote-gcs: invalid version: ${VERSION}" >&2
  exit 1
}
case "$PREFIX" in
  ""|/*|*/|*..*|*[!A-Za-z0-9._/-]*)
    echo "promote-gcs: unsafe prefix '$PREFIX'" >&2
    exit 1
    ;;
esac

work="$(mktemp -d)"
existing="${work}/existing"
trap 'rm -rf "$work"' EXIT HUP INT TERM

release_files | while IFS= read -r filename; do
  gcloud storage cp \
    "gs://${SOURCE_BUCKET}/${PREFIX}/releases/${VERSION}/${filename}" \
    "${work}/${filename}"
done

validate_release_directory "$work" promote-gcs
validate_release_directory "$RELEASE_DIR" promote-gcs
verify_release_identity "$RELEASE_DIR" "$work" promote-gcs

access_token="$(gcloud auth print-access-token)"
immutable_cache='public, max-age=31536000, immutable'
release_files | while IFS= read -r filename; do
  gcs_verify_exact \
    "${work}/${filename}" "$SOURCE_BUCKET" \
    "${PREFIX}/releases/${VERSION}/${filename}" \
    "$(release_content_type "$filename")" "$immutable_cache" \
    "$access_token" "$existing" promote-gcs
done

upload_immutable_release \
  "$work" "$DESTINATION_BUCKET" "$PREFIX" "$VERSION" \
  "$access_token" "$existing" promote-gcs
release_files | while IFS= read -r filename; do
  gcs_verify_exact \
    "${work}/${filename}" "$DESTINATION_BUCKET" \
    "${PREFIX}/releases/${VERSION}/${filename}" \
    "$(release_content_type "$filename")" "$immutable_cache" \
    "$access_token" "$existing" promote-gcs
done

echo "promote-gcs: promoted immutable ${VERSION} to gs://${DESTINATION_BUCKET}/${PREFIX}/releases/${VERSION}/" >&2
