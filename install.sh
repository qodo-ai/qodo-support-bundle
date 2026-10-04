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

usage() {
  cat <<'EOF'
Usage: sh install.sh [options]

Options:
  --version VERSION       Install an exact release instead of version.json
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
    if [ -n "$BACKUP_FILE" ] && [ -f "$BACKUP_FILE" ]; then
      mv -f "$BACKUP_FILE" "$TARGET" || true
      BACKUP_FILE=
    else
      rm -f "$TARGET"
    fi
  fi
  [ -z "$STAGED_FILE" ] || rm -f "$STAGED_FILE"
  [ -z "$BACKUP_FILE" ] || rm -f "$BACKUP_FILE"
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
  trap - EXIT HUP INT TERM
  cleanup_files "$status"
  exit "$status"
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

parse_version_json() {
  file=$1
  compact=$(awk '
    BEGIN {
      in_string = 0
      escaped = 0
    }
    {
      for (i = 1; i <= length($0); i++) {
        character = substr($0, i, 1)
        if (character == "\"" && !escaped) {
          in_string = !in_string
        }
        if (in_string || character !~ /[[:space:]]/) {
          printf "%s", character
        }
        if (character == "\\" && !escaped) {
          escaped = 1
        } else {
          escaped = 0
        }
      }
      if (in_string) {
        printf "\n"
      }
    }
    END {
      print ""
    }
  ' "$file")
  parsed=$(printf '%s\n' "$compact" |
    sed -n 's/^{"version":"\([^"]*\)"}$/\1/p')
  [ -n "$parsed" ] || die "version.json must contain only a string version property"
  validate_version "$parsed"
  printf '%s\n' "$parsed"
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

add_user_path() {
  directory=$1
  case "${SHELL-}" in
    */zsh) profile=$HOME/.zprofile ;;
    *) profile=$HOME/.profile ;;
  esac
  marker='# qodo-scout installer'
  if [ -f "$profile" ] && grep -Fqx "$marker" "$profile"; then
    printf 'PATH entry already exists in %s.\n' "$profile"
    return
  fi

  mkdir -p "$HOME"
  if [ -f "$profile" ]; then
    profile_backup=$(mktemp "$profile.qodo-scout.bak.XXXXXX") ||
      die "could not create profile backup"
    cp "$profile" "$profile_backup" ||
      die "could not back up $profile"
    printf 'Backed up %s to %s.\n' "$profile" "$profile_backup"
  fi
  escaped_directory=$(printf '%s' "$directory" | sed "s/'/'\\\\''/g")
  {
    printf '\n%s\n' "$marker"
    printf "export PATH='%s':\"\$PATH\"\n" "$escaped_directory"
  } >>"$profile" || die "could not update $profile"
  printf 'Added %s to PATH in %s.\n' "$directory" "$profile"
  printf 'Open a new terminal or run: . "%s"\n' "$profile"
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

if [ -n "$VERSION" ]; then
  validate_version "$VERSION"
fi
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

if [ -z "$VERSION" ]; then
  download "$BASE_URL/version.json" "$TEMP_DIR/version.json"
  VERSION=$(parse_version_json "$TEMP_DIR/version.json")
fi
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
if [ -e "$TARGET" ]; then
  BACKUP_FILE=$(mktemp "$INSTALL_DIR/.qodo-scout.backup.XXXXXX") ||
    die "could not create rollback file"
  cp -p "$TARGET" "$BACKUP_FILE" || die "could not preserve existing installation"
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
printf 'Run now with: "%s" collect --interactive\n' "$TARGET"
printf 'After PATH is active: qodo-scout collect --interactive\n'
