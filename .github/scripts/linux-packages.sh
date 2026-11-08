#!/usr/bin/env bash
# Builds the .deb and .rpm from an unpacked release archive:
# linux-packages.sh VERSION ARCHIVE_DIR OUT_DIR
# ARCHIVE_DIR holds gac, man/ and completions/, as in gac-redux-VERSION-TARGET.tar.gz. Needs nfpm
# and objdump on PATH.
set -euo pipefail

version=$1
src=$(cd "$2" && pwd)
out=$3

arch=$(objdump -f "$src/gac" | awk '/^architecture:/ { sub(",", "", $2); print $2 }')
case "$arch" in
  i386:x86-64) deb_arch=amd64 rpm_arch=x86_64 ;;
  aarch64) deb_arch=arm64 rpm_arch=aarch64 ;;
  *) echo "unknown architecture: $arch" >&2; exit 1 ;;
esac

# The dependencies come from the binary itself, so a new library or a newer build host can't
# slip into a package that claims less.
for lib in $(objdump -p "$src/gac" | awk '$1 == "NEEDED" { print $2 }'); do
  case "$lib" in
    libc.so.6 | libm.so.6 | ld-linux-*.so.*) ;; # glibc
    libgcc_s.so.1) ;;
    *) echo "gac links against $lib, which the packages don't declare" >&2; exit 1 ;;
  esac
done
glibc=$(objdump -T "$src/gac" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -1)
echo "gac needs glibc $glibc"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/man"
for page in "$src"/man/*.1; do
  name=$(basename "$page")
  gzip -9n < "$page" > "$work/man/$name.gz"
done

# Debian wants a copyright file and a changelog in the package's doc directory; an .rpm gets the
# changelog from nfpm.
cat > "$work/copyright" <<COPYRIGHT
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: gac-redux
Source: https://github.com/virtualmadden/gac-redux

Files: *
Copyright: 2026 virtualmadden
License: MIT or Apache-2.0
 The full texts are in /usr/share/doc/gac-redux/LICENSE-MIT and
 /usr/share/doc/gac-redux/LICENSE-APACHE.
COPYRIGHT

maintainer="Jonathan Madden <virtualmadden@users.noreply.github.com>"
release_notes=https://github.com/virtualmadden/gac-redux/releases/tag/v$version
# A pre-release is 0.5.0~beta.1 in a package, so it sorts before 0.5.0, as nfpm writes it.
gzip -9n > "$work/changelog.gz" <<CHANGELOG
gac-redux (${version/-/\~}) unstable; urgency=medium

  * $release_notes

 -- $maintainer  $(date -u -R)
CHANGELOG
cat > "$work/changelog.yaml" <<CHANGELOG
- semver: $version
  date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
  packager: $maintainer
  changes:
    - note: $release_notes
CHANGELOG

summary="Short-lived AWS credentials through IAM Identity Center"
body="gac signs in to AWS IAM Identity Center (AWS SSO) and writes a profile for
  every account and role you can use, in the files and formats the AWS CLI
  and SDKs read. It also runs commands as a role, prints role credentials for
  a shell, and opens the AWS console as a role."

# nfpm.yaml for one packager: a .deb's description starts with the summary line, an .rpm keeps
# the summary apart, and only an .rpm marks documentation and takes nfpm's changelog.
config() {
  local packager=$1 description doc="" changelog=""
  if [ "$packager" = deb ]; then
    description="$summary
  $body"
  else
    description=$body
    doc="type: doc"
    changelog="changelog: $work/changelog.yaml"
  fi
  cat <<YAML
name: gac-redux
arch: $deb_arch
platform: linux
version: $version
version_schema: semver
maintainer: $maintainer
description: |-
  $description
homepage: https://github.com/virtualmadden/gac-redux
license: MIT OR Apache-2.0
section: utils
$changelog
rpm:
  summary: $summary
contents:
  - src: $src/gac
    dst: /usr/bin/gac
    file_info: { mode: 0755 }
$(for page in "$work"/man/*.1.gz; do
  printf '  - src: %s\n    dst: /usr/share/man/man1/%s\n    %s\n' "$page" "$(basename "$page")" "$doc"
done)
  - src: $src/README.md
    dst: /usr/share/doc/gac-redux/README.md
    $doc
  - src: $src/completions/gac.bash
    dst: /usr/share/bash-completion/completions/gac
  - src: $src/completions/gac.fish
    dst: /usr/share/fish/vendor_completions.d/gac.fish
  - src: $src/completions/_gac
    dst: /usr/share/zsh/vendor-completions/_gac
    packager: deb
  - src: $src/completions/_gac
    dst: /usr/share/zsh/site-functions/_gac
    packager: rpm
  - src: $work/copyright
    dst: /usr/share/doc/gac-redux/copyright
    packager: deb
  - src: $work/changelog.gz
    dst: /usr/share/doc/gac-redux/changelog.gz
    packager: deb
  - src: $src/LICENSE-MIT
    dst: /usr/share/doc/gac-redux/LICENSE-MIT
    packager: deb
  - src: $src/LICENSE-APACHE
    dst: /usr/share/doc/gac-redux/LICENSE-APACHE
    packager: deb
  - src: $src/LICENSE-MIT
    dst: /usr/share/licenses/gac-redux/LICENSE-MIT
    type: license
    packager: rpm
  - src: $src/LICENSE-APACHE
    dst: /usr/share/licenses/gac-redux/LICENSE-APACHE
    type: license
    packager: rpm
overrides:
  deb:
    depends:
      - libc6 (>= $glibc)
      - libgcc-s1
  rpm:
    depends:
      - glibc >= $glibc
      - libgcc_s.so.1()(64bit)
YAML
}

mkdir -p "$out"
config deb > "$work/deb.yaml"
config rpm > "$work/rpm.yaml"
nfpm package --config "$work/deb.yaml" --packager deb --target "$out/gac-redux-$version-$deb_arch.deb"
nfpm package --config "$work/rpm.yaml" --packager rpm --target "$out/gac-redux-$version-$rpm_arch.rpm"
