#!/bin/sh
# Signs a draft release offline and publishes it.
#
#   scripts/sign-release.sh v0.1.0 ~/.ssh/nepomuk-release
#
# The key may also be a public key whose private half is in ssh-agent (e.g. on a hardware token).
# Requires the GitHub CLI (`gh`) logged in with write access to the repository.

set -eu

tag="${1:?usage: sign-release.sh <tag> <signing key>}"
key="${2:?usage: sign-release.sh <tag> <signing key>}"
repo="aleslanik2/nepomuk"
root=$(cd "$(dirname "$0")/.." && pwd)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "Downloading $tag from $repo"
gh release download "$tag" -R "$repo" -D "$work" -p '*.tar.gz' -p SHA256SUMS

# Sign only what is actually in the release.
cd "$work"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS
else
    shasum -a 256 -c SHA256SUMS
fi
listed=$(wc -l <SHA256SUMS | tr -d ' ')
present=$(ls -- *.tar.gz | wc -l | tr -d ' ')
[ "$listed" = "$present" ] || { echo "SHA256SUMS lists $listed archives, the release has $present" >&2; exit 1; }

echo
cat SHA256SUMS
echo
printf 'Sign and publish %s? [y/N] ' "$tag"
read -r answer
[ "$answer" = y ] || [ "$answer" = Y ] || { echo "aborted"; exit 1; }

ssh-keygen -Y sign -n nepomuk-release -f "$key" SHA256SUMS
"$root/scripts/release-signers.sh" verify SHA256SUMS SHA256SUMS.sig

gh release upload "$tag" -R "$repo" SHA256SUMS.sig --clobber
gh release edit "$tag" -R "$repo" --draft=false
echo "Published $tag"
