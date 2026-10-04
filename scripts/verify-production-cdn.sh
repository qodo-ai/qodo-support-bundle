#!/bin/sh
# Verify public CDN bytes and response metadata against the authenticated release.
set -eu

VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
RELEASE_DIR="${QODO_SUPPORT_BUNDLE_RELEASE_DIR:?QODO_SUPPORT_BUNDLE_RELEASE_DIR is required}"
BASE_URL="${QODO_SUPPORT_BUNDLE_BASE_URL:-https://get.qodo.ai/support-bundle}"
ROOT="$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/release-contract.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "${work}/cdn-release"

header_value() {
  name=$1
  file=$2
  awk -v wanted="$name" '
    {
      sub(/\r$/, "")
      separator = index($0, ":")
      if (separator > 0 &&
          tolower(substr($0, 1, separator - 1)) == tolower(wanted)) {
        value = substr($0, separator + 1)
        sub(/^[[:space:]]+/, "", value)
        result = value
      }
    }
    END { if (result != "") print result }
  ' "$file"
}

download_and_verify() {
  expected=$1
  url=$2
  content_type=$3
  cache_control=$4
  name=$5
  output="${work}/${name}"
  headers="${output}.headers"
  curl --fail --location --silent --show-error \
    --dump-header "$headers" --output "$output" "$url"
  cmp -s "$expected" "$output" || {
    echo "verify-production-cdn: bytes differ: ${url}" >&2
    return 1
  }
  [ "$(header_value Content-Type "$headers")" = "$content_type" ] || {
    echo "verify-production-cdn: unexpected Content-Type: ${url}" >&2
    return 1
  }
  [ "$(header_value Cache-Control "$headers")" = "$cache_control" ] || {
    echo "verify-production-cdn: unexpected Cache-Control: ${url}" >&2
    return 1
  }
}

immutable_cache='public, max-age=31536000, immutable'
release_files | while IFS= read -r filename; do
  download_and_verify \
    "${RELEASE_DIR}/${filename}" \
    "${BASE_URL}/releases/${VERSION}/${filename}" \
    "$(release_content_type "$filename")" "$immutable_cache" "cdn-release/${filename}"
done

mutable_cache='no-cache, max-age=0, must-revalidate'
release_installers | while IFS= read -r filename; do
  download_and_verify \
    "${RELEASE_DIR}/${filename}" "${BASE_URL}/${filename}" \
    'text/plain; charset=utf-8' "$mutable_cache" "stable-${filename}"
done

python3 "$ROOT/scripts/version-contract.py" render "$VERSION" > "${work}/expected-version.json"
download_and_verify \
  "${work}/expected-version.json" "${BASE_URL}/version.json" \
  application/json "$mutable_cache" version.json
(cd "${work}/cdn-release" && sha256sum --strict --check checksums.sha256)
(cd "${work}/cdn-release" && sha256sum --strict --check installer-checksums.sha256)
