#!/bin/sh
# Installs a package in a fresh distribution container, checks what it put where, and removes it:
# test-linux-package.sh PACKAGE VERSION
set -eu

package=$1
version=$2

case "$package" in
  *.deb)
    export DEBIAN_FRONTEND=noninteractive
    # Container images keep dpkg from installing man pages and docs; a full system installs them.
    sed -i '/^path-exclude/d' /etc/dpkg/dpkg.cfg.d/* 2> /dev/null || true
    apt-get -qq update
    apt-get -qq install -y "./$package"
    zsh_completion=/usr/share/zsh/vendor-completions/_gac
    remove() { apt-get -qq remove -y gac-redux; }
    ;;
  *.rpm)
    # As with dpkg, container images skip documentation, man pages included.
    dnf -q install -y --setopt=tsflags= "./$package"
    zsh_completion=/usr/share/zsh/site-functions/_gac
    remove() { dnf -q remove -y gac-redux; }
    ;;
  *) echo "not a package: $package" >&2; exit 1 ;;
esac

gac --version | grep -Fx "gac-redux $version"
gac --help > /dev/null
for file in /usr/share/man/man1/gac.1.gz /usr/share/man/man1/gac-sync.1.gz \
  /usr/share/bash-completion/completions/gac /usr/share/fish/vendor_completions.d/gac.fish \
  "$zsh_completion"; do
  test -s "$file" || { echo "missing: $file" >&2; exit 1; }
done

remove
if [ -e /usr/bin/gac ]; then
  echo "gac is still installed after removing the package" >&2
  exit 1
fi
echo "ok: $package"
