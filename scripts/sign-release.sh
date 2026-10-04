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
gh release download "$tag" -R "$repo" -D "$work"
rm -f "$work/SHA256SUMS.sig"

# Sign only what is actually in the release: every asset is listed and matches, nothing else.
cd "$work"
[ -f SHA256SUMS ] || { echo "the release has no SHA256SUMS" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS
else
    shasum -a 256 -c SHA256SUMS
fi
listed=$(sed 's/^[0-9a-f]*  *\*\{0,1\}//' SHA256SUMS | LC_ALL=C sort)
present=$(ls -- * | grep -vx SHA256SUMS | LC_ALL=C sort)
[ "$listed" = "$present" ] || {
    echo "SHA256SUMS and the release assets differ:" >&2
    printf 'listed:\n%s\npresent:\n%s\n' "$listed" "$present" >&2
    exit 1
}
for f in install.sh install.ps1; do
    printf '%s\n' "$present" | grep -qx "$f" || { echo "the release has no $f" >&2; exit 1; }
done

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
