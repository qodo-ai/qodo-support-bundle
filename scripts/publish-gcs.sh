#!/bin/sh
# Publish an authenticated release and metadata to the dev canary prefix.
set -eu

BUCKET="${QODO_SUPPORT_BUNDLE_BUCKET:-qodo-cli-public-dev}"
PREFIX="${QODO_SUPPORT_BUNDLE_PREFIX:-support-bundle}"
VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
PUBLICATION_OWNER="${QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER:?QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER is required}"
ROOT="$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)"
DIST="${QODO_SUPPORT_BUNDLE_DIST:-$ROOT/dist}"
. "$ROOT/scripts/gcs-exact-object.sh"
. "$ROOT/scripts/release-contract.sh"

python3 "$ROOT/scripts/version-contract.py" render "$VERSION" >/dev/null
case "$PREFIX" in
  ""|/*|*/|*..*|*[!A-Za-z0-9._/-]*)
    echo "publish-gcs: unsafe prefix '$PREFIX'" >&2
    exit 1
    ;;
esac

validate_release_directory "$DIST" publish-gcs

access_token="$(gcloud auth print-access-token)"
work="$(mktemp -d)"
PUBLICATION_LOCK_HELD=0
MUTABLE_ACTIVATION_STARTED=0
ACTIVATION_COMMITTED=0
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$PUBLICATION_LOCK_HELD" -eq 1 ]; then
    if [ "$status" -ne 0 ] &&
      [ "$MUTABLE_ACTIVATION_STARTED" -eq 1 ] &&
      [ "$ACTIVATION_COMMITTED" -eq 0 ]; then
      if ! repair_stable_installers \
        "$ROOT/scripts/version-contract.py" "$BUCKET" "$PREFIX" "$access_token" \
        "$work" "$existing" publish-gcs 1; then
        echo "publish-gcs: activation failed and stable installers could not be reconciled; publication lock retained for operator recovery" >&2
        rm -rf "$work"
        exit 1
      fi
      echo "publish-gcs: activation failed; stable installers were reconciled" >&2
    fi
    release_publication_lock \
      "$BUCKET" "$PREFIX" "$access_token" "$work" publish-gcs || status=1
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
existing="${work}/existing"
metadata="${work}/version.json"
current_metadata="${work}/current-version.json"
current_headers="${work}/current-version.headers"
python3 "$ROOT/scripts/version-contract.py" render "$VERSION" > "$metadata"

metadata_generation=0
if gcs_read_exact \
  "$BUCKET" "${PREFIX}/version.json" "$access_token" \
  "$current_metadata" "$current_headers" publish-gcs; then
  python3 "$ROOT/scripts/version-contract.py" \
    allow-update "$current_metadata" "$VERSION" >/dev/null
  metadata_generation="$(gcs_header_value x-goog-generation "$current_headers")"
  [ -n "$metadata_generation" ] || {
    echo "publish-gcs: version.json has no generation" >&2
    exit 1
  }
else
  read_status=$?
  [ "$read_status" -eq 1 ] || exit 1
fi

upload_immutable_release \
  "$DIST" "$BUCKET" "$PREFIX" "$VERSION" "$access_token" "$existing" publish-gcs

immutable_cache='public, max-age=31536000, immutable'
release_files | while IFS= read -r filename; do
  gcs_verify_exact \
    "${DIST}/${filename}" "$BUCKET" "${PREFIX}/releases/${VERSION}/${filename}" \
    "$(release_content_type "$filename")" "$immutable_cache" \
    "$access_token" "$existing" publish-gcs
done

acquire_publication_lock \
  "$PUBLICATION_OWNER" "$BUCKET" "$PREFIX" "$access_token" "$work" publish-gcs
MUTABLE_ACTIVATION_STARTED=1
repair_stable_installers \
  "$ROOT/scripts/version-contract.py" "$BUCKET" "$PREFIX" "$access_token" \
  "$work" "$existing" publish-gcs

# Recheck the pointer under the publication lock before changing stable objects.
metadata_generation=0
if gcs_read_exact \
  "$BUCKET" "${PREFIX}/version.json" "$access_token" \
  "$current_metadata" "$current_headers" publish-gcs; then
  python3 "$ROOT/scripts/version-contract.py" \
    allow-update "$current_metadata" "$VERSION" >/dev/null
  metadata_generation="$(gcs_header_value x-goog-generation "$current_headers")"
  [ -n "$metadata_generation" ] || {
    echo "publish-gcs: version.json has no generation" >&2
    exit 1
  }
else
  read_status=$?
  [ "$read_status" -eq 1 ] || exit 1
fi

mutable_cache='no-cache, max-age=0, must-revalidate'
release_installers | while IFS= read -r filename; do
  gcs_upload_mutable \
    "${DIST}/${filename}" "$BUCKET" "${PREFIX}/${filename}" \
    'text/plain; charset=utf-8' "$mutable_cache" \
    "$access_token" "$existing" publish-gcs
  gcs_verify_exact \
    "${DIST}/${filename}" "$BUCKET" "${PREFIX}/${filename}" \
    'text/plain; charset=utf-8' "$mutable_cache" \
    "$access_token" "$existing" publish-gcs
done

# The discoverable pointer is committed only after every release object validates.
gcs_upload_mutable \
  "$metadata" "$BUCKET" "${PREFIX}/version.json" \
  application/json "$mutable_cache" \
  "$access_token" "$existing" publish-gcs "$metadata_generation"
gcs_verify_exact \
  "$metadata" "$BUCKET" "${PREFIX}/version.json" \
  application/json "$mutable_cache" \
  "$access_token" "$existing" publish-gcs
ACTIVATION_COMMITTED=1

release_publication_lock \
  "$BUCKET" "$PREFIX" "$access_token" "$work" publish-gcs
echo "publish-gcs: published and activated ${VERSION} at gs://${BUCKET}/${PREFIX}/" >&2
