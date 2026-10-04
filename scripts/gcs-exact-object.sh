#!/bin/sh
# Exact-object, create-only Cloud Storage upload with byte-level idempotence.

gcs_upload_immutable() {
  source_path=$1
  bucket=$2
  object=$3
  content_type=$4
  expected_sha=$5
  access_token=$6
  existing=$7
  command_name=$8

  case "$bucket" in
    ""|*[!a-z0-9._-]*)
      echo "${command_name}: unsafe bucket '$bucket'" >&2
      return 1
      ;;
  esac
  case "$object" in
    ""|/*|*//*|*[!A-Za-z0-9._/+~-]*)
      echo "${command_name}: unsafe object '$object'" >&2
      return 1
      ;;
  esac

  endpoint="https://storage.googleapis.com/${bucket}/${object}"
  destination="gs://${bucket}/${object}"
  if curl \
    --fail \
    --silent \
    --show-error \
    --request PUT \
    --header "Authorization: Bearer ${access_token}" \
    --header "Content-Type: ${content_type}" \
    --header "Cache-Control: public, max-age=31536000, immutable" \
    --header "x-goog-if-generation-match: 0" \
    --upload-file "$source_path" \
    "$endpoint"; then
    return
  fi

  curl \
    --fail \
    --silent \
    --show-error \
    --request GET \
    --header "Authorization: Bearer ${access_token}" \
    --output "$existing" \
    "$endpoint" || {
      echo "${command_name}: immutable upload failed and existing object is unreadable: $destination" >&2
      return 1
    }
  actual_sha="$(sha256sum "$existing" | cut -d' ' -f1)"
  [ "$actual_sha" = "$expected_sha" ] || {
    echo "${command_name}: refusing to overwrite $destination" >&2
    echo "${command_name}: existing sha256 $actual_sha, expected $expected_sha" >&2
    return 1
  }
  echo "${command_name}: immutable object already matches: $destination" >&2
}
