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
mkdir "${work}/bin"

gcloud storage cp \
  "gs://${BUCKET}/${PREFIX}/releases/${EXPECTED_VERSION}/install.sh" \
  "${work}/install.sh"

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
case "$relative" in
  "releases/${QODO_SUPPORT_BUNDLE_VERSION}/checksums.sha256" | \
  "releases/${QODO_SUPPORT_BUNDLE_VERSION}/qodo-support-bundle-linux-amd64") ;;
  *) echo "dev canary curl: unexpected object: $relative" >&2; exit 2 ;;
esac
gcloud storage cp \
  "gs://${QODO_SUPPORT_BUNDLE_BUCKET}/${QODO_SUPPORT_BUNDLE_PREFIX}/${relative}" \
  "$destination"
EOF
chmod 700 "${work}/bin/curl"

PATH="${work}/bin:${PATH}" sh "${work}/install.sh" \
  --version "$EXPECTED_VERSION" \
  --install-dir "${work}/pinned"
pinned_version="$("${work}/pinned/qodo-scout" version)"
[ "$pinned_version" = "$EXPECTED_VERSION" ] || {
  echo "canary-dev-installers: pinned binary reports ${pinned_version}, expected ${EXPECTED_VERSION}" >&2
  exit 1
}
