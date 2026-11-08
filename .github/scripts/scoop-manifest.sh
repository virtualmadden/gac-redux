#!/usr/bin/env bash
# Prints the Scoop manifest for a release: scoop-manifest.sh VERSION SHA256SUMS
set -euo pipefail

version=$1
sums=$2
base="https://github.com/virtualmadden/gac-redux/releases/download/v$version"

# One architecture's entry: the zip, its checksum, and the folder inside it that holds gac.exe.
asset() {
  local dir="gac-redux-$version-$1"
  local sha
  sha=$(awk -v name="$dir.zip" '$2 == name { print $1 }' "$sums")
  if [ -z "$sha" ]; then
    echo "no checksum for $dir.zip in $sums" >&2
    exit 1
  fi
  jq -n --arg url "$base/$dir.zip" --arg hash "$sha" --arg dir "$dir" \
    '{url: $url, hash: $hash, extract_dir: $dir}'
}

x64=$(asset x86_64-pc-windows-msvc)
arm64=$(asset aarch64-pc-windows-msvc)
jq -n --arg version "$version" --argjson x64 "$x64" --argjson arm64 "$arm64" '{
  version: $version,
  description: "Short-lived AWS credentials through IAM Identity Center",
  homepage: "https://github.com/virtualmadden/gac-redux",
  license: "MIT|Apache-2.0",
  architecture: {"64bit": $x64, arm64: $arm64},
  bin: "gac.exe"
}'
