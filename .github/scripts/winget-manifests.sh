#!/usr/bin/env bash
# Writes the winget manifests for a release into OUT_DIR:
# winget-manifests.sh VERSION SHA256SUMS OUT_DIR
set -euo pipefail

version=$1
sums=$2
out=$3
id=virtualmadden.gac-redux
base="https://github.com/virtualmadden/gac-redux/releases/download/v$version"
schema="https://aka.ms/winget-manifest"
manifest_version=1.10.0

# One architecture's installer: the zip, its checksum, and gac.exe inside it.
installer() {
  local arch=$1 dir="gac-redux-$version-$2"
  local sha
  sha=$(awk -v name="$dir.zip" '$2 == name { print toupper($1) }' "$sums")
  if [ -z "$sha" ]; then
    echo "no checksum for $dir.zip in $sums" >&2
    exit 1
  fi
  cat <<YAML
- Architecture: $arch
  NestedInstallerFiles:
  - RelativeFilePath: $dir\\gac.exe
    PortableCommandAlias: gac
  InstallerUrl: $base/$dir.zip
  InstallerSha256: $sha
YAML
}

mkdir -p "$out"

cat > "$out/$id.yaml" <<YAML
# yaml-language-server: \$schema=$schema.version.$manifest_version.schema.json

PackageIdentifier: $id
PackageVersion: $version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: $manifest_version
YAML

cat > "$out/$id.installer.yaml" <<YAML
# yaml-language-server: \$schema=$schema.installer.$manifest_version.schema.json

PackageIdentifier: $id
PackageVersion: $version
InstallerType: zip
NestedInstallerType: portable
Commands:
- gac
ReleaseDate: $(date -u +%Y-%m-%d)
Installers:
$(installer x64 x86_64-pc-windows-msvc)
$(installer arm64 aarch64-pc-windows-msvc)
ManifestType: installer
ManifestVersion: $manifest_version
YAML

cat > "$out/$id.locale.en-US.yaml" <<YAML
# yaml-language-server: \$schema=$schema.defaultLocale.$manifest_version.schema.json

PackageIdentifier: $id
PackageVersion: $version
PackageLocale: en-US
Publisher: virtualmadden
PublisherUrl: https://github.com/virtualmadden
PublisherSupportUrl: https://github.com/virtualmadden/gac-redux/issues
PackageName: gac-redux
PackageUrl: https://github.com/virtualmadden/gac-redux
License: MIT OR Apache-2.0
LicenseUrl: https://github.com/virtualmadden/gac-redux#license
ShortDescription: Short-lived AWS credentials through IAM Identity Center
Description: |-
  gac signs in to AWS IAM Identity Center (AWS SSO) and writes a profile for every account and
  role you can use, in the files and formats the AWS CLI and SDKs read. It also runs commands as
  a role, prints role credentials for a shell, and opens the AWS console as a role.
Tags:
- aws
- aws-sso
- cli
- credentials
- iam-identity-center
ReleaseNotesUrl: https://github.com/virtualmadden/gac-redux/releases/tag/v$version
ManifestType: defaultLocale
ManifestVersion: $manifest_version
YAML
