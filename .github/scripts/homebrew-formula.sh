#!/usr/bin/env bash
# Prints the Homebrew formula for a release: homebrew-formula.sh VERSION SHA256SUMS
set -euo pipefail

version=$1
sums=$2
base="https://github.com/virtualmadden/gac-redux/releases/download/v$version"

asset() {
  local name="gac-redux-$version-$1.tar.gz"
  local sha
  sha=$(awk -v name="$name" '$2 == name { print $1 }' "$sums")
  if [ -z "$sha" ]; then
    echo "no checksum for $name in $sums" >&2
    exit 1
  fi
  printf '      url "%s/%s"\n      sha256 "%s"\n' "$base" "$name" "$sha"
}

cat <<FORMULA
class GacRedux < Formula
  desc "Short-lived AWS credentials through IAM Identity Center"
  homepage "https://github.com/virtualmadden/gac-redux"
  version "$version"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
$(asset aarch64-apple-darwin)
    end
    on_intel do
$(asset x86_64-apple-darwin)
    end
  end

  on_linux do
    on_arm do
$(asset aarch64-unknown-linux-gnu)
    end
    on_intel do
$(asset x86_64-unknown-linux-gnu)
    end
  end

  def install
    bin.install "gac"
  end

  test do
    assert_match "gac-redux #{version}", shell_output("#{bin}/gac --version")
  end
end
FORMULA
