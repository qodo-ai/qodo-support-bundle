#!/bin/sh
# Shared inventory and validation for authenticated release bytes.

release_binaries() {
  cat <<'EOF'
qodo-support-bundle-darwin-amd64
qodo-support-bundle-darwin-arm64
qodo-support-bundle-linux-amd64
qodo-support-bundle-linux-arm64
qodo-support-bundle-windows-amd64.exe
qodo-support-bundle-windows-arm64.exe
EOF
}

release_installers() {
  cat <<'EOF'
install.sh
install.ps1
EOF
}

release_files() {
  release_binaries
  printf '%s\n' checksums.sha256
  release_installers
  printf '%s\n' installer-checksums.sha256
}

release_content_type() {
  case "$1" in
    qodo-support-bundle-*) printf '%s\n' application/octet-stream ;;
    *) printf '%s\n' 'text/plain; charset=utf-8' ;;
  esac
}

validate_release_directory() {
  directory=$1
  command_name=$2
  expected_files="$(release_files | LC_ALL=C sort)"
  actual_files="$(
    find "$directory" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; |
      LC_ALL=C sort
  )"
  [ "$actual_files" = "$expected_files" ] || {
    echo "${command_name}: release inventory does not match the ten-file contract" >&2
    printf 'expected:\n%s\nactual:\n%s\n' "$expected_files" "$actual_files" >&2
    return 1
  }

  manifest_entries="$(
    awk '
      NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ { exit 1 }
      { print $2 }
    ' "$directory/checksums.sha256"
  )" || {
    echo "${command_name}: checksum manifest is malformed" >&2
    return 1
  }
  manifest_files="$(printf '%s\n' "$manifest_entries" | LC_ALL=C sort)"
  expected_binaries="$(release_binaries | LC_ALL=C sort)"
  [ "$manifest_files" = "$expected_binaries" ] || {
    echo "${command_name}: checksum manifest inventory does not match the six binaries" >&2
    return 1
  }

  installer_manifest_entries="$(
    awk '
      NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ { exit 1 }
      { print $2 }
    ' "$directory/installer-checksums.sha256"
  )" || {
    echo "${command_name}: installer checksum manifest is malformed" >&2
    return 1
  }
  installer_manifest_files="$(
    printf '%s\n' "$installer_manifest_entries" | LC_ALL=C sort
  )"
  expected_installers="$(release_installers | LC_ALL=C sort)"
  [ "$installer_manifest_files" = "$expected_installers" ] || {
    echo "${command_name}: installer checksum inventory does not match both installers" >&2
    return 1
  }

  (cd "$directory" && sha256sum --strict --check checksums.sha256)
  (cd "$directory" && sha256sum --strict --check installer-checksums.sha256)
}

upload_immutable_release() {
  directory=$1
  bucket=$2
  prefix=$3
  version=$4
  access_token=$5
  existing=$6
  command_name=$7
  release_files | while IFS= read -r filename; do
    source_path="${directory}/${filename}"
    object="${prefix}/releases/${version}/${filename}"
    content_type="$(release_content_type "$filename")"
    digest="$(sha256sum "$source_path" | cut -d' ' -f1)"
    gcs_upload_immutable \
      "$source_path" "$bucket" "$object" "$content_type" "$digest" \
      "$access_token" "$existing" "$command_name"
  done
}

verify_release_identity() {
  first=$1
  second=$2
  command_name=$3
  release_files | while IFS= read -r filename; do
    cmp -s "${first}/${filename}" "${second}/${filename}" || {
      echo "${command_name}: release bytes differ: ${filename}" >&2
      return 1
    }
  done
}

confirm_publication_lock() {
  desired=$1
  bucket=$2
  lock_object=$3
  access_token=$4
  current=$5
  headers=$6
  command_name=$7

  for attempt in 1 2 3; do
    if gcs_read_exact \
      "$bucket" "$lock_object" "$access_token" \
      "$current" "$headers" "$command_name"; then
      if gcs_object_matches \
        "$desired" "$current" "$headers" application/json no-store; then
        PUBLICATION_LOCK_GENERATION="$(
          gcs_header_value x-goog-generation "$headers"
        )"
        [ -n "$PUBLICATION_LOCK_GENERATION" ] || {
          echo "${command_name}: acquired publication lock has no generation" >&2
          return 1
        }
        PUBLICATION_LOCK_HELD=1
        return 0
      fi
      echo "${command_name}: publication lock is not owned by this publisher" >&2
      return 1
    fi
    [ "$attempt" -eq 3 ] || sleep 1
  done
  echo "${command_name}: publication lock verification failed after retries" >&2
  return 1
}

acquire_publication_lock() {
  owner=$1
  bucket=$2
  prefix=$3
  access_token=$4
  work=$5
  command_name=$6
  lock_object="${prefix}/control/publication-lock.json"
  lock_cache='no-store'
  desired="${work}/publication-lock-owned.json"
  current="${work}/publication-lock-current.json"
  headers="${current}.headers"

  case "$owner" in
    ""|*[!A-Za-z0-9._-]*)
      echo "${command_name}: unsafe publication owner '$owner'" >&2
      return 1
      ;;
  esac
  printf '{"owner":"%s"}\n' "$owner" >"$desired"

  if gcs_read_exact \
    "$bucket" "$lock_object" "$access_token" \
    "$current" "$headers" "$command_name"; then
    current_generation="$(gcs_header_value x-goog-generation "$headers")"
    [ -n "$current_generation" ] || {
      echo "${command_name}: publication lock has no generation" >&2
      return 1
    }
    if cmp -s "$desired" "$current"; then
      confirm_publication_lock \
        "$desired" "$bucket" "$lock_object" "$access_token" \
        "$current" "$headers" "$command_name"
      return
    fi
    unlocked="${work}/publication-lock-unlocked.json"
    printf '%s\n' '{"owner":""}' >"$unlocked"
    if ! cmp -s "$unlocked" "$current"; then
      echo "${command_name}: publication lock is held by another publisher" >&2
      return 1
    fi
  else
    read_status=$?
    [ "$read_status" -eq 1 ] || return 1
    current_generation=0
  fi

  gcs_conditional_put \
    "$desired" "$bucket" "$lock_object" application/json "$lock_cache" \
    "$current_generation" "$access_token" "$command_name" \
    "${work}/publication-lock-put.headers" || {
    echo "${command_name}: could not acquire publication lock" >&2
    return 1
  }
  PUBLICATION_LOCK_GENERATION="$(
    gcs_header_value \
      x-goog-generation "${work}/publication-lock-put.headers"
  )"
  if [ -z "$PUBLICATION_LOCK_GENERATION" ]; then
    confirm_publication_lock \
      "$desired" "$bucket" "$lock_object" "$access_token" \
      "$current" "$headers" "$command_name"
    return
  fi
  PUBLICATION_LOCK_HELD=1
  confirm_publication_lock \
    "$desired" "$bucket" "$lock_object" "$access_token" \
    "$current" "$headers" "$command_name"
}

release_publication_lock() {
  bucket=$1
  prefix=$2
  access_token=$3
  work=$4
  command_name=$5
  [ "${PUBLICATION_LOCK_HELD:-0}" -eq 1 ] || return 0
  unlocked="${work}/publication-lock-unlocked.json"
  printf '%s\n' '{"owner":""}' >"$unlocked"
  gcs_conditional_put \
    "$unlocked" "$bucket" "${prefix}/control/publication-lock.json" \
    application/json no-store "$PUBLICATION_LOCK_GENERATION" \
    "$access_token" "$command_name" || {
    echo "${command_name}: failed to release publication lock" >&2
    return 1
  }
  PUBLICATION_LOCK_HELD=0
}

repair_stable_installers() {
  version_script=$1
  bucket=$2
  prefix=$3
  access_token=$4
  work=$5
  existing=$6
  command_name=$7
  require_active_version=${8:-0}
  mutable_cache='no-cache, max-age=0, must-revalidate'
  immutable_cache='public, max-age=31536000, immutable'

  pointer="${work}/repair-version.json"
  pointer_headers="${work}/repair-version.headers"
  if gcs_read_exact \
    "$bucket" "${prefix}/version.json" "$access_token" \
    "$pointer" "$pointer_headers" "$command_name"; then
    :
  else
    read_status=$?
    if [ "$read_status" -eq 1 ]; then
      if [ "$require_active_version" -eq 1 ]; then
        echo "${command_name}: cannot reconcile stable installers without an active version" >&2
        return 1
      fi
      return 0
    fi
    return 1
  fi
  active_version="$(python3 "$version_script" read "$pointer")"

  release_installers | while IFS= read -r filename; do
    winner="${work}/repair-${filename}"
    winner_headers="${winner}.headers"
    gcs_read_exact \
      "$bucket" "${prefix}/releases/${active_version}/${filename}" \
      "$access_token" "$winner" "$winner_headers" "$command_name"
    if [ "$(gcs_header_value Content-Type "$winner_headers")" != \
      'text/plain; charset=utf-8' ] ||
      [ "$(gcs_header_value Cache-Control "$winner_headers")" != \
        "$immutable_cache" ]; then
      echo "${command_name}: active versioned installer has unexpected headers" >&2
      return 1
    fi
    gcs_upload_mutable \
      "$winner" "$bucket" "${prefix}/${filename}" \
      'text/plain; charset=utf-8' "$mutable_cache" \
      "$access_token" "$existing" "$command_name"
    gcs_verify_exact \
      "$winner" "$bucket" "${prefix}/${filename}" \
      'text/plain; charset=utf-8' "$mutable_cache" \
      "$access_token" "$existing" "$command_name"
  done
  echo "${command_name}: stable installers match active ${active_version}" >&2
}
