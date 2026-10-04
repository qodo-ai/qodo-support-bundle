#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
INSTALLER=$ROOT/install.sh
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/qodo-scout-install-test.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

passed=0

fail() {
  printf 'not ok - %s\n' "$1" >&2
  exit 1
}

pass() {
  passed=$((passed + 1))
  printf 'ok %d - %s\n' "$passed" "$1"
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

write_binary() {
  path=$1
  mkdir -p "$(dirname "$path")"
  cat >"$path" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_EXEC_LOG:?}"
case "${1-}" in
  version)
    printf '%s\n' 'fixture-version'
    [ "${FAKE_SMOKE_FAIL:-0}" != 1 ] || exit 92
    ;;
  *) exit 91 ;;
esac
EOF
  chmod 0755 "$path"
}

write_release() {
  directory=$1
  asset=$2
  mkdir -p "$directory"
  write_binary "$directory/$asset"
  printf '%s  %s\n' "$(sha256 "$directory/$asset")" "$asset" >"$directory/checksums.sha256"
}

write_fake_tools() {
  directory=$1
  mkdir -p "$directory"
  cat >"$directory/uname" <<'EOF'
#!/bin/sh
case "${1-}" in
  -s) printf '%s\n' "${FAKE_UNAME_S:?}" ;;
  -m) printf '%s\n' "${FAKE_UNAME_M:?}" ;;
  *) exit 2 ;;
esac
EOF
  cat >"$directory/curl" <<'EOF'
#!/bin/sh
set -eu
[ "${FAKE_CURL_FAIL:-0}" != 1 ] || exit 22
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--output) output=$2; shift 2 ;;
    --retry|--retry-delay|--connect-timeout) shift 2 ;;
    --proto|--proto-redir) shift 2 ;;
    --tlsv1.2|-f|-L|-fL|--fail|--location|--silent|--show-error) shift ;;
    https://*) url=$1; shift ;;
    *) exit 93 ;;
  esac
done
[ -n "$output" ] && [ -n "$url" ] || exit 94
printf '%s\n' "$url" >> "${FAKE_CURL_LOG:?}"
relative=${url#https://get.qodo.ai/support-bundle/}
cp "${FAKE_SERVER:?}/$relative" "$output"
EOF
  chmod 0755 "$directory/uname" "$directory/curl"
}

run_installer() {
  home=$1
  tools=$2
  shift 2
  HOME=$home \
    PATH="$tools:$PATH" \
    FAKE_UNAME_S=${FAKE_UNAME_S:-Darwin} \
    FAKE_UNAME_M=${FAKE_UNAME_M:-arm64} \
    FAKE_EXEC_LOG=$TEST_ROOT/exec.log \
    FAKE_CURL_LOG=$TEST_ROOT/curl.log \
    FAKE_SERVER=$TEST_ROOT/server \
    TMPDIR=$TEST_ROOT/tmp \
    sh "$INSTALLER" "$@"
}

mkdir -p "$TEST_ROOT/tmp" "$TEST_ROOT/server"
TOOLS=$TEST_ROOT/tools
write_fake_tools "$TOOLS"

LATEST_HOME="$TEST_ROOT/home with spaces"
LATEST_INSTALL="$LATEST_HOME/bin with spaces"
mkdir -p "$TEST_ROOT/server/releases/1.2.3"
printf '{ "version": "1.2.3" }\n' >"$TEST_ROOT/server/version.json"
write_release "$TEST_ROOT/server/releases/1.2.3" qodo-support-bundle-darwin-arm64
: >"$TEST_ROOT/exec.log"
: >"$TEST_ROOT/curl.log"
run_installer "$LATEST_HOME" "$TOOLS" --install-dir "$LATEST_INSTALL"
[ -x "$LATEST_INSTALL/qodo-scout" ] || fail "latest install did not create executable"
[ "$(stat -f '%Lp' "$LATEST_INSTALL/qodo-scout" 2>/dev/null || stat -c '%a' "$LATEST_INSTALL/qodo-scout")" = 755 ] ||
  fail "installed mode is not 0755"
[ "$(cat "$TEST_ROOT/exec.log")" = version ] || fail "smoke check ran a collecting command"
grep -Fx 'https://get.qodo.ai/support-bundle/version.json' "$TEST_ROOT/curl.log" >/dev/null ||
  fail "latest metadata URL was not fetched"
grep -Fx 'https://get.qodo.ai/support-bundle/releases/1.2.3/qodo-support-bundle-darwin-arm64' "$TEST_ROOT/curl.log" >/dev/null ||
  fail "versioned binary URL was not fetched"
[ -z "$(find "$TEST_ROOT/tmp" -mindepth 1 -maxdepth 1 -print)" ] ||
  fail "temporary directory was not cleaned"
pass "latest metadata installs and smoke-checks without collection"

: >"$TEST_ROOT/curl.log"
PINNED_INSTALL="$TEST_ROOT/pinned"
run_installer "$LATEST_HOME" "$TOOLS" --version 1.2.3 --install-dir "$PINNED_INSTALL"
if grep -F '/version.json' "$TEST_ROOT/curl.log" >/dev/null; then
  fail "pinned install fetched latest metadata"
fi
pass "pinned override bypasses version metadata"

for mapping in \
  'Darwin x86_64 qodo-support-bundle-darwin-amd64' \
  'Darwin arm64 qodo-support-bundle-darwin-arm64' \
  'Linux amd64 qodo-support-bundle-linux-amd64' \
  'Linux aarch64 qodo-support-bundle-linux-arm64'
do
  # The fixed mapping records intentionally split into three fields.
  # shellcheck disable=SC2086
  set -- $mapping
  os=$1
  arch=$2
  asset=$3
  source_dir="$TEST_ROOT/source $os $arch"
  write_release "$source_dir" "$asset"
  FAKE_UNAME_S=$os FAKE_UNAME_M=$arch \
    run_installer "$LATEST_HOME" "$TOOLS" \
      --version 9.8.7 \
      --source-dir "$source_dir" \
      --install-dir "$TEST_ROOT/install-$os-$arch" >/dev/null
done
pass "supported Unix OS and CPU mappings select exact assets"

if FAKE_UNAME_S=FreeBSD FAKE_UNAME_M=amd64 \
  run_installer "$LATEST_HOME" "$TOOLS" --version 1.2.3 --install-dir "$TEST_ROOT/unsupported" \
    >"$TEST_ROOT/unsupported.out" 2>&1; then
  fail "unsupported platform was accepted"
fi
grep -F 'unsupported platform' "$TEST_ROOT/unsupported.out" >/dev/null ||
  fail "unsupported platform error is unclear"
unset FAKE_UNAME_S FAKE_UNAME_M
pass "unsupported platforms fail closed"

BAD_SOURCE="$TEST_ROOT/bad checksum"
write_release "$BAD_SOURCE" qodo-support-bundle-darwin-arm64
mkdir -p "$TEST_ROOT/bad-install"
printf 'old\n' >"$TEST_ROOT/bad-install/qodo-scout"
printf '%064d  %s\n' 0 qodo-support-bundle-darwin-arm64 >"$BAD_SOURCE/checksums.sha256"
if run_installer "$LATEST_HOME" "$TOOLS" \
  --version 1.2.3 --source-dir "$BAD_SOURCE" --install-dir "$TEST_ROOT/bad-install" \
  >"$TEST_ROOT/mismatch.out" 2>&1; then
  fail "checksum mismatch was accepted"
fi
[ "$(cat "$TEST_ROOT/bad-install/qodo-scout")" = old ] ||
  fail "checksum failure replaced existing installation"
pass "checksum mismatch preserves existing installation"

SMOKE_SOURCE="$TEST_ROOT/smoke failure"
write_release "$SMOKE_SOURCE" qodo-support-bundle-darwin-arm64
mkdir -p "$TEST_ROOT/smoke-install"
printf 'old\n' >"$TEST_ROOT/smoke-install/qodo-scout"
if FAKE_SMOKE_FAIL=1 run_installer "$LATEST_HOME" "$TOOLS" \
  --version 1.2.3 --source-dir "$SMOKE_SOURCE" --install-dir "$TEST_ROOT/smoke-install" \
  >"$TEST_ROOT/smoke.out" 2>&1; then
  fail "failed smoke check was accepted"
fi
unset FAKE_SMOKE_FAIL
[ "$(cat "$TEST_ROOT/smoke-install/qodo-scout")" = old ] ||
  fail "failed smoke check did not restore the existing installation"
pass "failed smoke checks roll back an existing installation"

SYMLINK_INSTALL="$TEST_ROOT/symlink-install"
mkdir -p "$SYMLINK_INSTALL"
printf 'old\n' >"$SYMLINK_INSTALL/old-target"
ln -s old-target "$SYMLINK_INSTALL/qodo-scout"
if FAKE_SMOKE_FAIL=1 run_installer "$LATEST_HOME" "$TOOLS" \
  --version 1.2.3 --source-dir "$SMOKE_SOURCE" --install-dir "$SYMLINK_INSTALL" \
  >"$TEST_ROOT/symlink.out" 2>&1; then
  fail "failed symlink upgrade smoke check was accepted"
fi
unset FAKE_SMOKE_FAIL
[ -L "$SYMLINK_INSTALL/qodo-scout" ] ||
  fail "failed upgrade did not restore the prior symlink"
[ "$(readlink "$SYMLINK_INSTALL/qodo-scout")" = old-target ] ||
  fail "restored symlink points to the wrong target"
pass "failed smoke checks restore existing symlinks"

ROLLBACK_TOOLS=$TEST_ROOT/rollback-tools
cp -R "$TOOLS" "$ROLLBACK_TOOLS"
cat >"$ROLLBACK_TOOLS/mv" <<'EOF'
#!/bin/sh
for argument in "$@"; do
  case "$argument" in
    *.backup.*)
      [ "${FAKE_ROLLBACK_FAIL:-0}" != 1 ] || exit 95
      ;;
  esac
done
exec /bin/mv "$@"
EOF
chmod 0755 "$ROLLBACK_TOOLS/mv"
mkdir -p "$TEST_ROOT/rollback-install"
printf 'old\n' >"$TEST_ROOT/rollback-install/qodo-scout"
if FAKE_SMOKE_FAIL=1 FAKE_ROLLBACK_FAIL=1 \
  run_installer "$LATEST_HOME" "$ROLLBACK_TOOLS" \
    --version 1.2.3 \
    --source-dir "$SMOKE_SOURCE" \
    --install-dir "$TEST_ROOT/rollback-install" \
    >"$TEST_ROOT/rollback.out" 2>&1; then
  fail "failed rollback was accepted"
fi
unset FAKE_SMOKE_FAIL FAKE_ROLLBACK_FAIL
[ -n "$(find "$TEST_ROOT/rollback-install" -name '.qodo-scout.backup.*' -print)" ] ||
  fail "failed rollback deleted the preserved executable"
grep -F 'backup retained at' "$TEST_ROOT/rollback.out" >/dev/null ||
  fail "failed rollback did not report the preserved backup"
pass "failed rollback retains and reports the previous executable"

for kind in missing duplicate malformed; do
  source_dir="$TEST_ROOT/manifest-$kind"
  write_release "$source_dir" qodo-support-bundle-darwin-arm64
  case "$kind" in
    missing) : >"$source_dir/checksums.sha256" ;;
    duplicate)
      row=$(cat "$source_dir/checksums.sha256")
      printf '%s\n%s\n' "$row" "$row" >"$source_dir/checksums.sha256"
      ;;
    malformed) printf 'not-a-sha  %s\n' qodo-support-bundle-darwin-arm64 >"$source_dir/checksums.sha256" ;;
  esac
  if run_installer "$LATEST_HOME" "$TOOLS" \
    --version 1.2.3 --source-dir "$source_dir" --install-dir "$TEST_ROOT/install-$kind" \
    >"$TEST_ROOT/$kind.out" 2>&1; then
    fail "$kind checksum row was accepted"
  fi
done
pass "missing duplicate and malformed checksum rows are rejected"

printf '{ "version": "1.2.3", "extra": true }\n' >"$TEST_ROOT/server/version.json"
if run_installer "$LATEST_HOME" "$TOOLS" --install-dir "$TEST_ROOT/schema" \
  >"$TEST_ROOT/schema.out" 2>&1; then
  fail "version metadata with extra properties was accepted"
fi
pass "version metadata requires the strict minimal schema"

printf '{ "version": "../escape" }\n' >"$TEST_ROOT/server/version.json"
if run_installer "$LATEST_HOME" "$TOOLS" --install-dir "$TEST_ROOT/version" \
  >"$TEST_ROOT/version.out" 2>&1; then
  fail "unsafe version was accepted"
fi
pass "unsafe version strings are rejected"

printf '{ "version": "1.2. 3" }\n' >"$TEST_ROOT/server/version.json"
if run_installer "$LATEST_HOME" "$TOOLS" --install-dir "$TEST_ROOT/version-whitespace" \
  >"$TEST_ROOT/version-whitespace.out" 2>&1; then
  fail "whitespace inside a version string was normalized"
fi
pass "version metadata preserves and rejects value whitespace"

printf '{ "version": "1.2.3" }\n' >"$TEST_ROOT/server/version.json"
if FAKE_CURL_FAIL=1 run_installer "$LATEST_HOME" "$TOOLS" --install-dir "$TEST_ROOT/download" \
  >"$TEST_ROOT/download.out" 2>&1; then
  fail "download failure was ignored"
fi
unset FAKE_CURL_FAIL
[ -z "$(find "$TEST_ROOT/tmp" -mindepth 1 -maxdepth 1 -print)" ] ||
  fail "temporary directory remained after download failure"
pass "download failures stop installation"

MINIMAL_TOOLS=$TEST_ROOT/minimal-tools
mkdir -p "$MINIMAL_TOOLS"
for tool in awk chmod cp grep mkdir mktemp mv rm sed sh tr; do
  ln -s "$(command -v "$tool")" "$MINIMAL_TOOLS/$tool"
done
cp "$TOOLS/uname" "$MINIMAL_TOOLS/uname"
if HOME="$LATEST_HOME" \
  PATH="$MINIMAL_TOOLS" \
  FAKE_UNAME_S=Darwin \
  FAKE_UNAME_M=arm64 \
  TMPDIR="$TEST_ROOT/tmp" \
  sh "$INSTALLER" --install-dir "$TEST_ROOT/no-curl" \
    >"$TEST_ROOT/no-curl.out" 2>&1; then
  fail "network install without curl was accepted"
fi
grep -F 'curl is required' "$TEST_ROOT/no-curl.out" >/dev/null ||
  fail "missing curl error is unclear"
pass "missing curl fails with an actionable error"

NO_SHA_SOURCE=$TEST_ROOT/no-sha-source
write_release "$NO_SHA_SOURCE" qodo-support-bundle-darwin-arm64
if HOME="$LATEST_HOME" \
  PATH="$MINIMAL_TOOLS" \
  FAKE_UNAME_S=Darwin \
  FAKE_UNAME_M=arm64 \
  FAKE_EXEC_LOG="$TEST_ROOT/exec.log" \
  TMPDIR="$TEST_ROOT/tmp" \
  sh "$INSTALLER" \
    --version 1.2.3 \
    --source-dir "$NO_SHA_SOURCE" \
    --install-dir "$TEST_ROOT/no-sha" \
    >"$TEST_ROOT/no-sha.out" 2>&1; then
  fail "install without a SHA-256 tool was accepted"
fi
grep -F 'requires sha256sum or shasum' "$TEST_ROOT/no-sha.out" >/dev/null ||
  fail "missing SHA-256 tool error is unclear"
pass "missing checksum tools fail with an actionable error"

PROFILE_HOME="$TEST_ROOT/profile home"
PROFILE_SOURCE="$TEST_ROOT/profile source"
write_release "$PROFILE_SOURCE" qodo-support-bundle-darwin-arm64
SHELL=/bin/zsh run_installer "$PROFILE_HOME" "$TOOLS" \
  --version 1.2.3 --source-dir "$PROFILE_SOURCE" --add-to-path >/dev/null
SHELL=/bin/zsh run_installer "$PROFILE_HOME" "$TOOLS" \
  --version 1.2.3 --source-dir "$PROFILE_SOURCE" --add-to-path >/dev/null
[ "$(grep -c '^# qodo-scout installer$' "$PROFILE_HOME/.zprofile")" -eq 1 ] ||
  fail "PATH profile update was not idempotent"
pass "opt-in PATH update is user-local and idempotent"

SESSION_HOME="$TEST_ROOT/session-only-path"
SESSION_INSTALL="$SESSION_HOME/.local/bin"
PATH="$SESSION_INSTALL:$PATH" SHELL=/bin/zsh \
  run_installer "$SESSION_HOME" "$TOOLS" \
    --version 1.2.3 --source-dir "$PROFILE_SOURCE" --add-to-path >/dev/null
[ "$(grep -c '^# qodo-scout installer$' "$SESSION_HOME/.zprofile")" -eq 1 ] ||
  fail "a session-only PATH entry prevented persistent opt-in"
pass "opt-in PATH persists entries present only in the current session"

SECOND_INSTALL="$PROFILE_HOME/second bin"
SHELL=/bin/zsh run_installer "$PROFILE_HOME" "$TOOLS" \
  --version 1.2.3 \
  --source-dir "$PROFILE_SOURCE" \
  --install-dir "$SECOND_INSTALL" \
  --add-to-path >/dev/null
grep -F "export PATH='$SECOND_INSTALL':\"\$PATH\"" "$PROFILE_HOME/.zprofile" >/dev/null ||
  fail "a second install directory was not persisted"
pass "PATH persistence handles a later custom install directory"

BASH_HOME="$TEST_ROOT/bash-home"
mkdir -p "$BASH_HOME"
printf '# existing bash profile\n' >"$BASH_HOME/.bash_profile"
SHELL=/bin/bash run_installer "$BASH_HOME" "$TOOLS" \
  --version 1.2.3 --source-dir "$PROFILE_SOURCE" --add-to-path >/dev/null
grep -F '# qodo-scout installer' "$BASH_HOME/.bash_profile" >/dev/null ||
  fail "existing bash profile was not selected"
pass "PATH persistence selects an existing bash profile"

LINK_HOME="$TEST_ROOT/link-home"
mkdir -p "$LINK_HOME"
printf '# linked profile\n' >"$LINK_HOME/profile-target"
ln -s profile-target "$LINK_HOME/.zprofile"
SHELL=/bin/zsh run_installer "$LINK_HOME" "$TOOLS" \
  --version 1.2.3 --source-dir "$PROFILE_SOURCE" --add-to-path >/dev/null
[ -L "$LINK_HOME/.zprofile" ] ||
  fail "PATH update replaced a profile symlink"
grep -F '# qodo-scout installer' "$LINK_HOME/profile-target" >/dev/null ||
  fail "PATH update did not update the linked profile target"
pass "PATH persistence preserves profile symlinks"

LOCK_HOME="$TEST_ROOT/lock-home"
mkdir -p "$LOCK_HOME/.zprofile.qodo-scout.lock"
(
  sleep 1
  rmdir "$LOCK_HOME/.zprofile.qodo-scout.lock"
) &
lock_releaser=$!
SHELL=/bin/zsh run_installer "$LOCK_HOME" "$TOOLS" \
  --version 1.2.3 --source-dir "$PROFILE_SOURCE" --add-to-path >/dev/null
wait "$lock_releaser"
grep -F '# qodo-scout installer' "$LOCK_HOME/.zprofile" >/dev/null ||
  fail "PATH update did not continue after the profile lock was released"
pass "PATH persistence serializes profile updates"

TIMEOUT_HOME="$TEST_ROOT/timeout-home"
mkdir -p "$TIMEOUT_HOME/.zprofile.qodo-scout.lock"
if SHELL=/bin/zsh run_installer "$TIMEOUT_HOME" "$TOOLS" \
  --version 1.2.3 --source-dir "$PROFILE_SOURCE" --add-to-path \
  >"$TEST_ROOT/lock-timeout.out" 2>&1; then
  fail "installer ignored an active profile lock"
fi
[ -d "$TIMEOUT_HOME/.zprofile.qodo-scout.lock" ] ||
  fail "lock timeout removed a lock owned by another installer"
pass "profile lock timeouts preserve the active owner's lock"

SPECIAL_INSTALL="$TEST_ROOT/\$(touch should-not-run)'quoted"
run_installer "$LATEST_HOME" "$TOOLS" \
  --version 1.2.3 \
  --source-dir "$PROFILE_SOURCE" \
  --install-dir "$SPECIAL_INSTALL" >"$TEST_ROOT/special-path.out"
expected_special=$(printf '%s' "$SPECIAL_INSTALL/qodo-scout" | sed "s/'/'\\\\''/g")
grep -F "Run now with: '$expected_special' collect --interactive" \
  "$TEST_ROOT/special-path.out" >/dev/null ||
  fail "printed command did not quote shell metacharacters safely"
pass "printed full-path command is shell-safe"

printf '1..%d\n' "$passed"
