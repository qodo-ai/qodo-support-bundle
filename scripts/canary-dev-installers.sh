#!/bin/sh
# Exercise pinned and metadata-selected installers against exact dev objects.
set -eu

BUCKET="${QODO_SUPPORT_BUNDLE_BUCKET:-qodo-cli-public-dev}"
PREFIX="${QODO_SUPPORT_BUNDLE_PREFIX:-support-bundle}"
export QODO_SUPPORT_BUNDLE_BUCKET="$BUCKET"
export QODO_SUPPORT_BUNDLE_PREFIX="$PREFIX"
EXPECTED_VERSION="${QODO_SUPPORT_BUNDLE_VERSION:?QODO_SUPPORT_BUNDLE_VERSION is required}"
ROOT="$(unset CDPATH; cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
release="${work}/release"
mkdir "$release" "${work}/bin"

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
pinned_version="$("${work}/pinned/qodo-scout" version)"
[ "$pinned_version" = "$EXPECTED_VERSION" ] || {
  echo "canary-dev-installers: pinned binary reports ${pinned_version}, expected ${EXPECTED_VERSION}" >&2
  exit 1
}

cat >"${work}/bin/curl" <<'EOF'
#!/bin/sh
set -eu
destination=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--output) destination=$2; shift 2 ;;
    https://get.qodo.ai/support-bundle/*) url=$1; shift ;;
    -fL|--fail|--location|--tlsv1.2) shift ;;
    --proto|--proto-redir|--retry|--retry-delay) shift 2 ;;
    *) echo "dev canary curl: unexpected argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$destination" ] && [ -n "$url" ] || exit 2
relative=${url#https://get.qodo.ai/support-bundle/}
gcloud storage cp \
  "gs://${QODO_SUPPORT_BUNDLE_BUCKET}/${QODO_SUPPORT_BUNDLE_PREFIX}/${relative}" \
  "$destination"
EOF
chmod 700 "${work}/bin/curl"

PATH="${work}/bin:${PATH}" sh "${work}/install.sh" \
  --install-dir "${work}/metadata"
metadata_version="$("${work}/metadata/qodo-scout" version)"
[ "$metadata_version" = "$EXPECTED_VERSION" ] || {
  echo "canary-dev-installers: metadata-selected binary reports ${metadata_version}, expected ${EXPECTED_VERSION}" >&2
  exit 1
}
