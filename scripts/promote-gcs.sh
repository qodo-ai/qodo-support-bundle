#!/bin/sh
# Promote byte-identical dev-canary assets to the production bucket.
set -eu

SOURCE_BUCKET="${QODO_SUPPORT_BUNDLE_SOURCE_BUCKET:-qodo-cli-public-dev}"
DESTINATION_BUCKET="${QODO_SUPPORT_BUNDLE_DESTINATION_BUCKET:-qodo-cli-public}"
PREFIX="${QODO_SUPPORT_BUNDLE_PREFIX:-support-bundle}"
VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
RELEASE_DIR="${QODO_SUPPORT_BUNDLE_RELEASE_DIR:?QODO_SUPPORT_BUNDLE_RELEASE_DIR is required}"
ROOT="$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/gcs-exact-object.sh"

case "$VERSION" in
  -*) echo "promote-gcs: version must not start with '-'" >&2; exit 1 ;;
  *[!A-Za-z0-9.+-]*) echo "promote-gcs: version contains unsafe characters" >&2; exit 1 ;;
esac
case "$PREFIX" in
  ""|/*|*/|*..*|*[!A-Za-z0-9._/-]*)
    echo "promote-gcs: unsafe prefix '$PREFIX'" >&2
    exit 1
    ;;
esac

expected_binaries='qodo-support-bundle-darwin-amd64
qodo-support-bundle-darwin-arm64
qodo-support-bundle-linux-amd64
qodo-support-bundle-linux-arm64
qodo-support-bundle-windows-amd64.exe
qodo-support-bundle-windows-arm64.exe'
expected_files="checksums.sha256
${expected_binaries}"

work="$(mktemp -d)"
existing="${work}/existing"
trap 'rm -rf "$work"' EXIT

printf '%s\n' "$expected_files" | while IFS= read -r filename; do
  gcloud storage cp \
    "gs://${SOURCE_BUCKET}/${PREFIX}/releases/${VERSION}/${filename}" \
    "${work}/${filename}"
done

actual_files="$(
  find "$work" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; |
    LC_ALL=C sort
)"
[ "$actual_files" = "$expected_files" ] || {
  echo "promote-gcs: downloaded inventory does not match the release contract" >&2
  exit 1
}

if ! awk '
    NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ { exit 1 }
    { print $2 }
  ' "$work/checksums.sha256" > "$work/canary-manifest-files"; then
  echo "promote-gcs: checksum manifest is malformed" >&2
  exit 1
fi
manifest_files="$(LC_ALL=C sort "$work/canary-manifest-files")"
[ "$manifest_files" = "$expected_binaries" ] || {
  echo "promote-gcs: checksum manifest inventory does not match the six binaries" >&2
  exit 1
}

(cd "$work" && sha256sum --strict --check checksums.sha256)

release_files="$(
  find "$RELEASE_DIR" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; |
    LC_ALL=C sort
)"
[ "$release_files" = "$expected_files" ] || {
  echo "promote-gcs: authenticated release inventory does not match the release contract" >&2
  exit 1
}

if ! awk '
    NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ { exit 1 }
    { print $2 }
  ' "$RELEASE_DIR/checksums.sha256" > "$work/release-manifest-files"; then
  echo "promote-gcs: authenticated release checksum manifest is malformed" >&2
  exit 1
fi
release_manifest_files="$(LC_ALL=C sort "$work/release-manifest-files")"
[ "$release_manifest_files" = "$expected_binaries" ] || {
  echo "promote-gcs: authenticated release checksum inventory does not match the six binaries" >&2
  exit 1
}
(cd "$RELEASE_DIR" && sha256sum --strict --check checksums.sha256)

printf '%s\n' "$expected_files" | while IFS= read -r filename; do
  cmp -s "${RELEASE_DIR}/${filename}" "${work}/${filename}" || {
    echo "promote-gcs: dev canary differs from authenticated release: ${filename}" >&2
    exit 1
  }
done

access_token="$(gcloud auth print-access-token)"

printf '%s\n' "$expected_binaries" | while IFS= read -r filename; do
  source_path="${work}/${filename}"
  object="${PREFIX}/releases/${VERSION}/${filename}"
  digest="$(sha256sum "$source_path" | cut -d' ' -f1)"
  gcs_upload_immutable \
    "$source_path" "$DESTINATION_BUCKET" "$object" application/octet-stream "$digest" \
    "$access_token" "$existing" promote-gcs
done

filename=checksums.sha256
source_path="${work}/${filename}"
object="${PREFIX}/releases/${VERSION}/${filename}"
digest="$(sha256sum "$source_path" | cut -d' ' -f1)"
gcs_upload_immutable \
  "$source_path" "$DESTINATION_BUCKET" "$object" text/plain "$digest" \
  "$access_token" "$existing" promote-gcs

echo "promote-gcs: promoted ${VERSION} to gs://${DESTINATION_BUCKET}/${PREFIX}/releases/${VERSION}/" >&2
