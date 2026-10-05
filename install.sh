#!/bin/sh
set -eu

BASE_URL=https://get.qodo.ai/support-bundle
VERSION=
SOURCE_DIR=
INSTALL_DIR=${XDG_BIN_HOME:-${HOME:?HOME is required}/.local/bin}
ADD_TO_PATH=0
TEMP_DIR=
STAGED_FILE=
BACKUP_FILE=
TARGET=
INSTALLED=0
BACKUP_PRESERVED=0
PROFILE_STAGED=
PROFILE_LOCK=
SIGNALS_DEFERRED=0
PENDING_SIGNAL=

usage() {
  cat <<'EOF'
Usage: sh install.sh [options]

Options:
  --version VERSION       Install the required exact release
  --source-dir DIRECTORY  Install from a local binary and checksums.sha256
  --install-dir DIRECTORY Install to a user-owned directory
  --add-to-path           Add the install directory to the user shell profile
  -h, --help              Show this help
EOF
}

die() {
  printf 'qodo-scout installer: %s\n' "$*" >&2
  exit 1
}

cleanup_files() {
  status=$1
  if [ "$status" -ne 0 ] && [ "$INSTALLED" -eq 1 ]; then
    if [ -n "$BACKUP_FILE" ] &&
      { [ -e "$BACKUP_FILE" ] || [ -L "$BACKUP_FILE" ]; }; then
      if mv -f "$BACKUP_FILE" "$TARGET"; then
        BACKUP_FILE=
      else
        BACKUP_PRESERVED=1
        printf 'qodo-scout installer: rollback failed; backup retained at %s\n' \
          "$BACKUP_FILE" >&2
      fi
    else
      rm -f "$TARGET"
    fi
  fi
  [ -z "$STAGED_FILE" ] || rm -f "$STAGED_FILE"
  [ -z "$PROFILE_STAGED" ] || rm -f "$PROFILE_STAGED"
  [ -z "$PROFILE_LOCK" ] || rmdir "$PROFILE_LOCK" 2>/dev/null || true
  if [ "$BACKUP_PRESERVED" -eq 0 ] && [ -n "$BACKUP_FILE" ]; then
    rm -f "$BACKUP_FILE"
  fi
  [ -z "$TEMP_DIR" ] || rm -rf "$TEMP_DIR"
}

on_exit() {
  status=$?
  trap - EXIT HUP INT TERM
  cleanup_files "$status"
  exit "$status"
}

on_signal() {
  status=$1
  if [ "$SIGNALS_DEFERRED" -eq 1 ]; then
    PENDING_SIGNAL=$status
    return
  fi
  trap - EXIT HUP INT TERM
  cleanup_files "$status"
  exit "$status"
}

finish_deferred_signals() {
  SIGNALS_DEFERRED=0
  if [ -n "$PENDING_SIGNAL" ]; then
    status=$PENDING_SIGNAL
    PENDING_SIGNAL=
    on_signal "$status"
  fi
}

trap on_exit EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

require_value() {
  option=$1
  value=${2-}
  [ -n "$value" ] || die "$option requires a non-empty value"
}

validate_version() {
  value=$1
  printf '%s\n' "$value" |
    grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$' ||
    die "invalid version: $value"
}

download() {
  url=$1
  destination=$2
  curl -fL \
    --proto '=https' \
    --proto-redir '=https' \
    --tlsv1.2 \
    --retry 3 \
    --retry-delay 1 \
    -o "$destination" \
    "$url" ||
    die "download failed: $url"
}

manifest_digest() {
  manifest=$1
  asset=$2
  awk -v target="$asset" '
    {
      count = split($0, fields, /[[:space:]]+/)
      if (fields[count] != target) {
        next
      }
      matches++
      if (count != 2 || length(fields[1]) != 64 ||
          fields[1] ~ /[^0-9A-Fa-f]/) {
        malformed = 1
      } else {
        digest = fields[1]
      }
    }
    END {
      if (malformed) {
        print "checksum row for " target " is malformed" > "/dev/stderr"
        exit 2
      }
      if (matches != 1) {
        print "expected exactly one checksum row for " target > "/dev/stderr"
        exit 3
      }
      print digest
    }
  ' "$manifest"
}

actual_digest() {
  file=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    die "SHA-256 verification requires sha256sum or shasum"
  fi
}

path_contains() {
  candidate=$1
  case ":${PATH-}:" in
    *":$candidate:"*) return 0 ;;
    *) return 1 ;;
  esac
}

shell_literal() {
  escaped=$(printf '%s' "$1" | sed "s/'/'\\\\''/g")
  printf "'%s'" "$escaped"
}

resolve_profile_path() {
  current=$1
  links=0
  while [ -L "$current" ]; do
    links=$((links + 1))
    [ "$links" -le 20 ] || die "profile symlink chain is too deep: $1"
    link=$(readlink "$current") || die "could not read profile symlink: $current"
    case "$link" in
      /*) current=$link ;;
      *)
        parent=$(CDPATH='' cd -- "$(dirname "$current")" && pwd -P) ||
          die "could not resolve profile directory"
        current=$parent/$link
        ;;
    esac
  done
  printf '%s\n' "$current"
}

release_profile_lock() {
  [ -z "$PROFILE_LOCK" ] || rmdir "$PROFILE_LOCK" ||
    die "could not release profile lock: $PROFILE_LOCK"
  PROFILE_LOCK=
}

add_user_path() {
  directory=$1
  case "${SHELL-}" in
    */zsh) profile=$HOME/.zprofile ;;
    */bash)
      if [ -f "$HOME/.bash_profile" ]; then
        profile=$HOME/.bash_profile
      else
        profile=$HOME/.profile
      fi
      ;;
    *) profile=$HOME/.profile ;;
  esac
  mkdir -p "$HOME"
  profile_lock_path=$profile.qodo-scout.lock
  lock_attempt=0
  while :; do
    SIGNALS_DEFERRED=1
    if mkdir "$profile_lock_path" 2>/dev/null; then
      PROFILE_LOCK=$profile_lock_path
      finish_deferred_signals
      break
    fi
    finish_deferred_signals
    lock_attempt=$((lock_attempt + 1))
    [ "$lock_attempt" -lt 5 ] ||
      die "profile update is locked; retry after removing stale lock $profile_lock_path"
    sleep 1
  done
  profile_file=$(resolve_profile_path "$profile")
  marker='# qodo-scout installer'
  directory_literal=$(shell_literal "$directory")
  # Keep $PATH literal for the shell that loads the profile.
  # shellcheck disable=SC2016
  export_line=$(printf 'export PATH=%s:"$PATH"' "$directory_literal")
  if [ -f "$profile_file" ] && grep -Fqx "$export_line" "$profile_file"; then
    printf 'PATH entry already exists in %s.\n' "$profile"
    release_profile_lock
    return
  fi

  if [ -f "$profile_file" ]; then
    profile_backup=$(mktemp "$profile_file.qodo-scout.bak.XXXXXX") ||
      die "could not create profile backup"
    cp "$profile_file" "$profile_backup" ||
      die "could not back up $profile_file"
    printf 'Backed up %s to %s.\n' "$profile_file" "$profile_backup"
  fi
  PROFILE_STAGED=$(mktemp "$profile_file.qodo-scout.new.XXXXXX") ||
    die "could not stage profile update"
  if [ -f "$profile_file" ]; then
    cp -p "$profile_file" "$PROFILE_STAGED" ||
      die "could not stage $profile_file"
  fi
  {
    printf '\n%s\n' "$marker"
    printf '%s\n' "$export_line"
  } >>"$PROFILE_STAGED" || die "could not stage PATH update"
  mv -f "$PROFILE_STAGED" "$profile_file" || die "could not update $profile_file"
  PROFILE_STAGED=
  release_profile_lock
  printf 'Added %s to PATH in %s.\n' "$directory" "$profile"
  profile_literal=$(shell_literal "$profile")
  printf 'Open a new terminal or run: . %s\n' "$profile_literal"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      require_value "$1" "${2-}"
      VERSION=$2
      shift 2
      ;;
    --version=*)
      VERSION=${1#*=}
      require_value --version "$VERSION"
      shift
      ;;
    --source-dir)
      require_value "$1" "${2-}"
      SOURCE_DIR=$2
      shift 2
      ;;
    --source-dir=*)
      SOURCE_DIR=${1#*=}
      require_value --source-dir "$SOURCE_DIR"
      shift
      ;;
    --install-dir)
      require_value "$1" "${2-}"
      INSTALL_DIR=$2
      shift 2
      ;;
    --install-dir=*)
      INSTALL_DIR=${1#*=}
      require_value --install-dir "$INSTALL_DIR"
      shift
      ;;
    --add-to-path)
      ADD_TO_PATH=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

case "$INSTALL_DIR" in
  /*) ;;
  *) die "install directory must be an absolute path" ;;
esac

[ -n "$VERSION" ] || die "--version is required; install an explicit release"
validate_version "$VERSION"
if [ -n "$SOURCE_DIR" ]; then
  [ -n "$VERSION" ] ||
    die "--source-dir requires --version so the local release is explicit"
  case "$SOURCE_DIR" in
    /*) ;;
    *) die "source directory must be an absolute path" ;;
  esac
  [ -d "$SOURCE_DIR" ] || die "source directory does not exist: $SOURCE_DIR"
else
  command -v curl >/dev/null 2>&1 || die "curl is required for network installation"
fi

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) die "unsupported platform: $(uname -s) $(uname -m)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) die "unsupported platform: $(uname -s) $(uname -m)" ;;
esac
asset=qodo-support-bundle-$os-$arch

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/qodo-scout.XXXXXX") ||
  die "could not create a private temporary directory"
chmod 0700 "$TEMP_DIR" || die "could not secure temporary directory"

release_url=$BASE_URL/releases/$VERSION
binary=$TEMP_DIR/$asset
manifest=$TEMP_DIR/checksums.sha256

if [ -n "$SOURCE_DIR" ]; then
  cp "$SOURCE_DIR/$asset" "$binary" ||
    die "local source is missing $asset"
  cp "$SOURCE_DIR/checksums.sha256" "$manifest" ||
    die "local source is missing checksums.sha256"
else
  download "$release_url/$asset" "$binary"
  download "$release_url/checksums.sha256" "$manifest"
fi

expected=$(manifest_digest "$manifest" "$asset") ||
  die "checksum manifest validation failed"
actual=$(actual_digest "$binary")
expected=$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')
actual=$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')
[ "$actual" = "$expected" ] ||
  die "checksum verification failed for the selected Qodo Scout artifact"

mkdir -p "$INSTALL_DIR" || die "could not create install directory: $INSTALL_DIR"
STAGED_FILE=$(mktemp "$INSTALL_DIR/.qodo-scout.XXXXXX") ||
  die "could not stage installation in $INSTALL_DIR"
cp "$binary" "$STAGED_FILE" || die "could not stage verified executable"
chmod 0755 "$STAGED_FILE" || die "could not set executable permissions"

TARGET=$INSTALL_DIR/qodo-scout
if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
  BACKUP_FILE=$(mktemp "$INSTALL_DIR/.qodo-scout.backup.XXXXXX") ||
    die "could not create rollback file"
  if [ -L "$TARGET" ]; then
    rm -f "$BACKUP_FILE"
    cp -P -p "$TARGET" "$BACKUP_FILE" ||
      die "could not preserve existing installation"
  else
    cp -p "$TARGET" "$BACKUP_FILE" ||
      die "could not preserve existing installation"
  fi
fi
mv -f "$STAGED_FILE" "$TARGET" || die "could not install qodo-scout"
STAGED_FILE=
INSTALLED=1

if ! "$TARGET" version; then
  die "installed qodo-scout failed its non-collecting version check"
fi
INSTALLED=0
if [ -n "$BACKUP_FILE" ]; then
  rm -f "$BACKUP_FILE"
  BACKUP_FILE=
fi

printf 'Installed Qodo Scout %s to %s\n' "$VERSION" "$TARGET"
if [ "$ADD_TO_PATH" -eq 1 ]; then
  add_user_path "$INSTALL_DIR"
elif ! path_contains "$INSTALL_DIR"; then
  printf '%s is not on PATH.\n' "$INSTALL_DIR"
  printf 'Re-run with --add-to-path, or add it to your user PATH.\n'
fi
target_literal=$(shell_literal "$TARGET")
printf 'Run now with: %s collect --interactive\n' "$target_literal"
printf 'After PATH is active: qodo-scout collect --interactive\n'
