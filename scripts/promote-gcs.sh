#!/bin/sh
# Promote byte-identical dev-canary assets and activate production metadata.
set -eu

SOURCE_BUCKET="${QODO_SUPPORT_BUNDLE_SOURCE_BUCKET:-qodo-cli-public-dev}"
DESTINATION_BUCKET="${QODO_SUPPORT_BUNDLE_DESTINATION_BUCKET:-qodo-cli-public}"
PREFIX="${QODO_SUPPORT_BUNDLE_PREFIX:-support-bundle}"
VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
PUBLICATION_OWNER="${QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER:?QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER is required}"
RELEASE_DIR="${QODO_SUPPORT_BUNDLE_RELEASE_DIR:?QODO_SUPPORT_BUNDLE_RELEASE_DIR is required}"
ROOT="$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/gcs-exact-object.sh"
. "$ROOT/scripts/release-contract.sh"

python3 "$ROOT/scripts/version-contract.py" render "$VERSION" >/dev/null
case "$PREFIX" in
  ""|/*|*/|*..*|*[!A-Za-z0-9._/-]*)
    echo "promote-gcs: unsafe prefix '$PREFIX'" >&2
    exit 1
    ;;
esac

work="$(mktemp -d)"
existing="${work}/existing"
access_token=
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
        "$ROOT/scripts/version-contract.py" "$DESTINATION_BUCKET" "$PREFIX" \
        "$access_token" "$work" "$existing" promote-gcs 1; then
        echo "promote-gcs: activation failed and stable installers could not be reconciled; publication lock retained for operator recovery" >&2
        rm -rf "$work"
        exit 1
      fi
      echo "promote-gcs: activation failed; stable installers were reconciled" >&2
    fi
    release_publication_lock \
      "$DESTINATION_BUCKET" "$PREFIX" "$access_token" "$work" promote-gcs ||
      status=1
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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

mutable_cache='no-cache, max-age=0, must-revalidate'
release_installers | while IFS= read -r filename; do
  gcs_verify_exact \
    "${work}/${filename}" "$SOURCE_BUCKET" "${PREFIX}/${filename}" \
    'text/plain; charset=utf-8' "$mutable_cache" \
    "$access_token" "$existing" promote-gcs
done

dev_metadata="${work}/dev-version.json"
dev_headers="${work}/dev-version.headers"
gcs_read_exact \
  "$SOURCE_BUCKET" "${PREFIX}/version.json" "$access_token" \
  "$dev_metadata" "$dev_headers" promote-gcs
dev_version="$(
  python3 "$ROOT/scripts/version-contract.py" \
    allow-update "$dev_metadata" "$VERSION"
)"
[ "$dev_version" = "$VERSION" ] || {
  echo "promote-gcs: dev version.json does not select ${VERSION}" >&2
  exit 1
}
gcs_verify_exact \
  "$dev_metadata" "$SOURCE_BUCKET" "${PREFIX}/version.json" \
  application/json "$mutable_cache" "$access_token" "$existing" promote-gcs

metadata="${work}/production-version.json"
current_metadata="${work}/current-production-version.json"
current_headers="${work}/current-production-version.headers"
python3 "$ROOT/scripts/version-contract.py" render "$VERSION" > "$metadata"
metadata_generation=0
if gcs_read_exact \
  "$DESTINATION_BUCKET" "${PREFIX}/version.json" "$access_token" \
  "$current_metadata" "$current_headers" promote-gcs; then
  python3 "$ROOT/scripts/version-contract.py" \
    allow-update "$current_metadata" "$VERSION" >/dev/null
  metadata_generation="$(gcs_header_value x-goog-generation "$current_headers")"
  [ -n "$metadata_generation" ] || {
    echo "promote-gcs: production version.json has no generation" >&2
    exit 1
  }
else
  read_status=$?
  [ "$read_status" -eq 1 ] || exit 1
fi

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

acquire_publication_lock \
  "$PUBLICATION_OWNER" "$DESTINATION_BUCKET" "$PREFIX" "$access_token" \
  "$work" promote-gcs
MUTABLE_ACTIVATION_STARTED=1
repair_stable_installers \
  "$ROOT/scripts/version-contract.py" "$DESTINATION_BUCKET" "$PREFIX" \
  "$access_token" "$work" "$existing" promote-gcs

# Recheck the pointer under the publication lock before changing stable objects.
metadata_generation=0
if gcs_read_exact \
  "$DESTINATION_BUCKET" "${PREFIX}/version.json" "$access_token" \
  "$current_metadata" "$current_headers" promote-gcs; then
  python3 "$ROOT/scripts/version-contract.py" \
    allow-update "$current_metadata" "$VERSION" >/dev/null
  metadata_generation="$(gcs_header_value x-goog-generation "$current_headers")"
  [ -n "$metadata_generation" ] || {
    echo "promote-gcs: production version.json has no generation" >&2
    exit 1
  }
else
  read_status=$?
  [ "$read_status" -eq 1 ] || exit 1
fi

release_installers | while IFS= read -r filename; do
  gcs_upload_mutable \
    "${work}/${filename}" "$DESTINATION_BUCKET" "${PREFIX}/${filename}" \
    'text/plain; charset=utf-8' "$mutable_cache" \
    "$access_token" "$existing" promote-gcs
  gcs_verify_exact \
    "${work}/${filename}" "$DESTINATION_BUCKET" "${PREFIX}/${filename}" \
    'text/plain; charset=utf-8' "$mutable_cache" \
    "$access_token" "$existing" promote-gcs
done

# The production pointer is last and retains the generation observed pre-promotion.
gcs_upload_mutable \
  "$metadata" "$DESTINATION_BUCKET" "${PREFIX}/version.json" \
  application/json "$mutable_cache" "$access_token" "$existing" \
  promote-gcs "$metadata_generation"
gcs_verify_exact \
  "$metadata" "$DESTINATION_BUCKET" "${PREFIX}/version.json" \
  application/json "$mutable_cache" "$access_token" "$existing" promote-gcs
ACTIVATION_COMMITTED=1

release_publication_lock \
  "$DESTINATION_BUCKET" "$PREFIX" "$access_token" "$work" promote-gcs
echo "promote-gcs: promoted and activated ${VERSION} at gs://${DESTINATION_BUCKET}/${PREFIX}/" >&2
