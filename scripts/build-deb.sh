#!/bin/sh
# Build on Debian 13 with dependencies from debian/control installed.
set -eu

repository=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
workspace=$(mktemp -d /tmp/pkimaster-build.XXXXXXXX)
trap 'rm -r -- "$workspace"' EXIT INT TERM
mkdir "$workspace/source"
cd "$repository"
# Stage explicitly to avoid copying local PKI state, virtual environments or
# repository history, and to support sources on WSL's Windows filesystem.
cp -R app.py enterprise.py identity.py mfa.py pki.py key_backends.py key_storage.py audit_integrity.py security.py pkimaster_server.py wsgi.py pyproject.toml \
    MANIFEST.in README.md docs templates static tests debian scripts "$workspace/source/"
find "$workspace/source" -type f -exec chmod 0644 {} +
chmod 0755 "$workspace/source/debian/rules" "$workspace/source/debian/postinst" "$workspace/source/debian/postrm"
cd "$workspace/source"
dpkg-buildpackage --build=binary --no-sign
package_version=$(dpkg-parsechangelog -SVersion)
install -d "$repository/dist"
for artifact in "$workspace"/pkimaster_*.deb "$workspace"/pkimaster_*.buildinfo "$workspace"/pkimaster_*.changes; do
    install -m 0644 "$artifact" "$repository/dist/"
done
echo "APT package: $repository/dist/pkimaster_${package_version}_all.deb"
