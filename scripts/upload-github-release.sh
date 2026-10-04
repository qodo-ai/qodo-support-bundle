#!/bin/sh
# Add release assets without replacing an existing name.
set -eu

tag=${1:?release tag is required}
directory=${2:?release asset directory is required}
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

assets="$(
  gh release view "$tag" --json assets --jq '.assets[].name' |
    LC_ALL=C sort
)"

find "$directory" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; |
  LC_ALL=C sort |
  while IFS= read -r name; do
    source_path="${directory}/${name}"
    case "
${assets}
" in
      *"
${name}
"*)
        gh release download "$tag" --pattern "$name" --dir "$work"
        cmp -s "$source_path" "${work}/${name}" || {
          echo "upload-github-release: existing asset differs: ${name}" >&2
          exit 1
        }
        echo "upload-github-release: existing asset matches: ${name}" >&2
        ;;
      *)
        if ! gh release upload "$tag" "$source_path"; then
          rm -f "${work}/${name}"
          gh release download "$tag" --pattern "$name" --dir "$work"
          cmp -s "$source_path" "${work}/${name}" || {
            echo "upload-github-release: concurrent asset conflict: ${name}" >&2
            exit 1
          }
          echo "upload-github-release: concurrent identical asset accepted: ${name}" >&2
        fi
        ;;
    esac
  done
