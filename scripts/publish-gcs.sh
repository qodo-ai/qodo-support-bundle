#!/bin/sh
# Publish one verified release to the dev canary bucket under an isolated prefix.
set -eu

BUCKET="${QODO_SUPPORT_BUNDLE_BUCKET:-qodo-cli-public-dev}"
PREFIX="${QODO_SUPPORT_BUNDLE_PREFIX:-support-bundle}"
VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
ROOT="$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)"
DIST="${QODO_SUPPORT_BUNDLE_DIST:-$ROOT/dist}"

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
qodo-support-bundle-windows-amd64.exe'
expected_files="checksums.sha256
${expected_binaries}"

actual_files="$(
  find "$DIST" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; |
    LC_ALL=C sort
)"
[ "$actual_files" = "$expected_files" ] || {
  echo "publish-gcs: dist inventory does not match the release contract" >&2
  printf 'expected:\n%s\nactual:\n%s\n' "$expected_files" "$actual_files" >&2
  exit 1
}

manifest_files="$(
  awk '
    NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ { exit 1 }
    { print $2 }
  ' "$DIST/checksums.sha256" |
    LC_ALL=C sort
)" || {
  echo "publish-gcs: checksum manifest is malformed" >&2
  exit 1
}
[ "$manifest_files" = "$expected_binaries" ] || {
  echo "publish-gcs: checksum manifest inventory does not match the five binaries" >&2
  printf 'expected:\n%s\nactual:\n%s\n' "$expected_binaries" "$manifest_files" >&2
  exit 1
}

(cd "$DIST" && sha256sum --check checksums.sha256)

existing="$(mktemp)"
trap 'rm -f "$existing"' EXIT

upload_immutable() {
  source_path=$1
  destination=$2
  content_type=$3
  expected_sha=$4

  if gcloud storage cp \
    --content-type="$content_type" \
    --cache-control="public, max-age=31536000, immutable" \
    --if-generation-match=0 \
    "$source_path" "$destination"; then
    return
  fi

  gcloud storage cp "$destination" "$existing" || {
    echo "publish-gcs: immutable upload failed and existing object is unreadable: $destination" >&2
    return 1
  }
  actual_sha="$(sha256sum "$existing" | cut -d' ' -f1)"
  [ "$actual_sha" = "$expected_sha" ] || {
    echo "publish-gcs: refusing to overwrite $destination" >&2
    echo "publish-gcs: existing sha256 $actual_sha, expected $expected_sha" >&2
    return 1
  }
  echo "publish-gcs: immutable object already matches: $destination" >&2
}

printf '%s\n' "$expected_binaries" | while IFS= read -r filename; do
  source_path="${DIST}/${filename}"
  destination="gs://${BUCKET}/${PREFIX}/releases/${VERSION}/${filename}"
  digest="$(sha256sum "$source_path" | cut -d' ' -f1)"
  upload_immutable "$source_path" "$destination" application/octet-stream "$digest"
done

filename=checksums.sha256
source_path="${DIST}/${filename}"
destination="gs://${BUCKET}/${PREFIX}/releases/${VERSION}/${filename}"
digest="$(sha256sum "$source_path" | cut -d' ' -f1)"
upload_immutable "$source_path" "$destination" text/plain "$digest"

echo "publish-gcs: published ${VERSION} to gs://${BUCKET}/${PREFIX}/releases/${VERSION}/" >&2
