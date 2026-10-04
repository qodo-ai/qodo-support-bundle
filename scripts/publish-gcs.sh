#!/bin/sh
# Publish one verified release to the dev canary bucket under an isolated prefix.
set -eu

BUCKET="${QODO_SUPPORT_BUNDLE_BUCKET:-qodo-cli-public-dev}"
PREFIX="${QODO_SUPPORT_BUNDLE_PREFIX:-support-bundle}"
VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
ROOT="$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)"
DIST="${QODO_SUPPORT_BUNDLE_DIST:-$ROOT/dist}"
. "$ROOT/scripts/gcs-exact-object.sh"

case "$VERSION" in
  -*) echo "publish-gcs: version must not start with '-'" >&2; exit 1 ;;
  *[!A-Za-z0-9.+-]*) echo "publish-gcs: version contains unsafe characters" >&2; exit 1 ;;
esac
case "$PREFIX" in
  ""|/*|*/|*..*|*[!A-Za-z0-9._/-]*)
    echo "publish-gcs: unsafe prefix '$PREFIX'" >&2
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

manifest_entries="$(mktemp)"
existing="$(mktemp)"
trap 'rm -f "$manifest_entries" "$existing"' EXIT

actual_files="$(
  find "$DIST" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; |
    LC_ALL=C sort
)"
[ "$actual_files" = "$expected_files" ] || {
  echo "publish-gcs: dist inventory does not match the release contract" >&2
  printf 'expected:\n%s\nactual:\n%s\n' "$expected_files" "$actual_files" >&2
  exit 1
}

if ! awk '
    NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ { exit 1 }
    { print $2 }
  ' "$DIST/checksums.sha256" > "$manifest_entries"; then
  echo "publish-gcs: checksum manifest is malformed" >&2
  exit 1
fi
manifest_files="$(LC_ALL=C sort "$manifest_entries")"
[ "$manifest_files" = "$expected_binaries" ] || {
  echo "publish-gcs: checksum manifest inventory does not match the six binaries" >&2
  printf 'expected:\n%s\nactual:\n%s\n' "$expected_binaries" "$manifest_files" >&2
  exit 1
}

(cd "$DIST" && sha256sum --strict --check checksums.sha256)

access_token="$(gcloud auth print-access-token)"

printf '%s\n' "$expected_binaries" | while IFS= read -r filename; do
  source_path="${DIST}/${filename}"
  object="${PREFIX}/releases/${VERSION}/${filename}"
  digest="$(sha256sum "$source_path" | cut -d' ' -f1)"
  gcs_upload_immutable \
    "$source_path" "$BUCKET" "$object" application/octet-stream "$digest" \
    "$access_token" "$existing" publish-gcs
done

filename=checksums.sha256
source_path="${DIST}/${filename}"
object="${PREFIX}/releases/${VERSION}/${filename}"
digest="$(sha256sum "$source_path" | cut -d' ' -f1)"
gcs_upload_immutable \
  "$source_path" "$BUCKET" "$object" text/plain "$digest" \
  "$access_token" "$existing" publish-gcs

echo "publish-gcs: published ${VERSION} to gs://${BUCKET}/${PREFIX}/releases/${VERSION}/" >&2
