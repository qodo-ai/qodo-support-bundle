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

repair_stable_installers() {
  version_script=$1
  bucket=$2
  prefix=$3
  access_token=$4
  work=$5
  existing=$6
  command_name=$7
  mutable_cache='no-cache, max-age=0, must-revalidate'
  immutable_cache='public, max-age=31536000, immutable'

  for attempt in 1 2 3; do
    pointer="${work}/repair-version-${attempt}.json"
    pointer_headers="${work}/repair-version-${attempt}.headers"
    gcs_read_exact \
      "$bucket" "${prefix}/version.json" "$access_token" \
      "$pointer" "$pointer_headers" "$command_name"
    pointer_generation="$(gcs_header_value x-goog-generation "$pointer_headers")"
    active_version="$(python3 "$version_script" read "$pointer")"

    release_installers | while IFS= read -r filename; do
      winner="${work}/repair-${attempt}-${filename}"
      winner_headers="${winner}.headers"
      gcs_read_exact \
        "$bucket" "${prefix}/releases/${active_version}/${filename}" \
        "$access_token" "$winner" "$winner_headers" "$command_name"
      [ "$(gcs_header_value Content-Type "$winner_headers")" = \
        'text/plain; charset=utf-8' ] &&
        [ "$(gcs_header_value Cache-Control "$winner_headers")" = \
          "$immutable_cache" ] || {
        echo "${command_name}: active versioned installer has unexpected headers" >&2
        return 1
      }
      gcs_upload_mutable \
        "$winner" "$bucket" "${prefix}/${filename}" \
        'text/plain; charset=utf-8' "$mutable_cache" \
        "$access_token" "$existing" "$command_name"
      gcs_verify_exact \
        "$winner" "$bucket" "${prefix}/${filename}" \
        'text/plain; charset=utf-8' "$mutable_cache" \
        "$access_token" "$existing" "$command_name"
    done

    after="${work}/repair-after-${attempt}.json"
    after_headers="${work}/repair-after-${attempt}.headers"
    gcs_read_exact \
      "$bucket" "${prefix}/version.json" "$access_token" \
      "$after" "$after_headers" "$command_name"
    after_generation="$(gcs_header_value x-goog-generation "$after_headers")"
    if [ "$after_generation" = "$pointer_generation" ]; then
      echo "${command_name}: restored stable installers for ${active_version}" >&2
      return 0
    fi
  done
  echo "${command_name}: version pointer kept changing during installer repair" >&2
  return 1
}
