#!/bin/sh
# Exact-object Cloud Storage reads and conditional writes without bucket listing.

gcs_validate_name() {
  bucket=$1
  object=$2
  command_name=$3
  case "$bucket" in
    "" | *[!a-z0-9._-]*)
      echo "${command_name}: unsafe bucket '$bucket'" >&2
      return 1
      ;;
  esac
  case "$object" in
    "" | /* | *//* | *[!A-Za-z0-9._/+~-]*)
      echo "${command_name}: unsafe object '$object'" >&2
      return 1
      ;;
  esac
}

gcs_header_value() {
  header_name=$1
  header_file=$2
  awk -v wanted="$header_name" '
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
    END {
      if (result != "") print result
    }
  ' "$header_file"
}

gcs_read_exact() {
  bucket=$1
  object=$2
  access_token=$3
  output=$4
  headers=$5
  command_name=$6
  gcs_validate_name "$bucket" "$object" "$command_name" || return 2
  endpoint="https://storage.googleapis.com/${bucket}/${object}"

  status="$(
    curl \
      --silent \
      --show-error \
      --request GET \
      --header "Authorization: Bearer ${access_token}" \
      --dump-header "$headers" \
      --output "$output" \
      --write-out '%{http_code}' \
      "$endpoint"
  )" || return 2
  case "$status" in
    200) return 0 ;;
    404)
      rm -f "$output"
      return 1
      ;;
    *)
      echo "${command_name}: exact-object read returned HTTP ${status}: gs://${bucket}/${object}" >&2
      return 2
      ;;
  esac
}

gcs_object_matches() {
  expected_path=$1
  existing_path=$2
  headers=$3
  content_type=$4
  cache_control=$5
  cmp -s "$expected_path" "$existing_path" &&
    [ "$(gcs_header_value Content-Type "$headers")" = "$content_type" ] &&
    [ "$(gcs_header_value Cache-Control "$headers")" = "$cache_control" ]
}

gcs_conditional_put() {
  source_path=$1
  bucket=$2
  object=$3
  content_type=$4
  cache_control=$5
  generation=$6
  access_token=$7
  command_name=$8
  gcs_validate_name "$bucket" "$object" "$command_name" || return 1
  endpoint="https://storage.googleapis.com/${bucket}/${object}"

  curl \
    --fail \
    --silent \
    --show-error \
    --request PUT \
    --header "Authorization: Bearer ${access_token}" \
    --header "Content-Type: ${content_type}" \
    --header "Cache-Control: ${cache_control}" \
    --header "x-goog-if-generation-match: ${generation}" \
    --upload-file "$source_path" \
    "$endpoint"
}

gcs_upload_immutable() {
  source_path=$1
  bucket=$2
  object=$3
  content_type=$4
  expected_sha=$5
  access_token=$6
  existing=$7
  command_name=$8
  cache_control='public, max-age=31536000, immutable'
  headers="${existing}.headers"

  if gcs_conditional_put \
    "$source_path" "$bucket" "$object" "$content_type" "$cache_control" 0 \
    "$access_token" "$command_name"; then
    return
  fi

  if ! gcs_read_exact \
    "$bucket" "$object" "$access_token" "$existing" "$headers" "$command_name"; then
    echo "${command_name}: immutable upload failed and existing object is unreadable: gs://${bucket}/${object}" >&2
    return 1
  fi
  actual_sha="$(sha256sum "$existing" | cut -d' ' -f1)"
  if [ "$actual_sha" = "$expected_sha" ] &&
    gcs_object_matches "$source_path" "$existing" "$headers" "$content_type" "$cache_control"; then
    echo "${command_name}: immutable object already matches: gs://${bucket}/${object}" >&2
    return
  fi

  echo "${command_name}: refusing to overwrite gs://${bucket}/${object}" >&2
  echo "${command_name}: existing sha256 $actual_sha, expected $expected_sha" >&2
  return 1
}

gcs_upload_mutable() {
  source_path=$1
  bucket=$2
  object=$3
  content_type=$4
  cache_control=$5
  access_token=$6
  existing=$7
  command_name=$8
  expected_generation=${9-}
  headers="${existing}.headers"

  if gcs_read_exact \
    "$bucket" "$object" "$access_token" "$existing" "$headers" "$command_name"; then
    observed_generation="$(gcs_header_value x-goog-generation "$headers")"
    [ -n "$observed_generation" ] || {
      echo "${command_name}: existing object has no generation: gs://${bucket}/${object}" >&2
      return 1
    }
    if [ -n "$expected_generation" ] &&
      [ "$observed_generation" != "$expected_generation" ]; then
      echo "${command_name}: generation changed for gs://${bucket}/${object}" >&2
      return 1
    fi
    if gcs_object_matches \
      "$source_path" "$existing" "$headers" "$content_type" "$cache_control"; then
      echo "${command_name}: mutable object already matches: gs://${bucket}/${object}" >&2
      return
    fi
  else
    read_status=$?
    [ "$read_status" -eq 1 ] || return 1
    observed_generation=0
  fi

  generation=${expected_generation:-$observed_generation}
  if ! gcs_conditional_put \
    "$source_path" "$bucket" "$object" "$content_type" "$cache_control" \
    "$generation" "$access_token" "$command_name"; then
    echo "${command_name}: conditional write conflict for gs://${bucket}/${object}" >&2
    return 1
  fi
}

gcs_verify_exact() {
  expected_path=$1
  bucket=$2
  object=$3
  content_type=$4
  cache_control=$5
  access_token=$6
  existing=$7
  command_name=$8
  headers="${existing}.headers"

  if ! gcs_read_exact \
    "$bucket" "$object" "$access_token" "$existing" "$headers" "$command_name"; then
    echo "${command_name}: published object is unreadable: gs://${bucket}/${object}" >&2
    return 1
  fi
  if ! gcs_object_matches \
    "$expected_path" "$existing" "$headers" "$content_type" "$cache_control"; then
    echo "${command_name}: published bytes or headers differ: gs://${bucket}/${object}" >&2
    return 1
  fi
}
