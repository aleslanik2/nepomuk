#!/bin/sh
# Release signing keys embedded in install.sh and install.ps1.
#
#   scripts/release-signers.sh show                 print the allowed_signers lines
#   scripts/release-signers.sh check                both installers carry the same, non-empty keys
#   scripts/release-signers.sh verify <file> <sig>  verify a release signature against them

set -eu

root=$(cd "$(dirname "$0")/.." && pwd)

from_sh() {
    sed -n "/^RELEASE_SIGNERS='/,/^'/p" "$root/install.sh" | sed "1d;\$d" | sed '/^[[:space:]]*$/d'
}

from_ps1() {
    sed -n "/^\$ReleaseSigners = @'/,/^'@/p" "$root/install.ps1" | sed "1d;\$d" | tr -d '\r' | sed '/^[[:space:]]*$/d'
}

case "${1:-}" in
    show)
        from_sh
        ;;
    check)
        a=$(from_sh)
        b=$(from_ps1)
        [ -n "$a" ] || { echo "install.sh has no release signing key (RELEASE_SIGNERS)" >&2; exit 1; }
        [ "$a" = "$b" ] || { echo "install.sh and install.ps1 carry different release keys" >&2; exit 1; }
        echo "release keys OK:"
        printf '%s\n' "$a"
        ;;
    verify)
        file="${2:?file}"
        sig="${3:?signature}"
        tmp=$(mktemp)
        trap 'rm -f "$tmp"' EXIT
        from_sh >"$tmp"
        [ -s "$tmp" ] || { echo "install.sh has no release signing key" >&2; exit 1; }
        principal=$(sed -n '1{s/[[:space:]].*//;p;}' "$tmp")
        ssh-keygen -Y verify -f "$tmp" -I "$principal" -n nepomuk-release -s "$sig" <"$file"
        ;;
    *)
        echo "usage: $0 show | check | verify <file> <sig>" >&2
        exit 2
        ;;
esac
