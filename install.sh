#!/bin/sh
# nepomuk installer for Linux, macOS and Windows (Git Bash / MSYS2 / Cygwin).
#
#   curl -fsSL https://raw.githubusercontent.com/aleslanik2/nepomuk/main/install.sh | sh
#   sh install.sh --version v0.1.0 --dir /usr/local/bin
#
# The binary is installed only after its SHA-256 matches SHA256SUMS and SHA256SUMS carries a
# valid release signature (`ssh-keygen -Y verify`, namespace "nepomuk-release"), or after it
# matches a hash pinned with --sha256 / NEPOMUK_SHA256 (recommended in CI, §15.5).
#
# Private repository: with GH_TOKEN or GITHUB_TOKEN set and the GitHub CLI (`gh`) installed, the
# release is downloaded through `gh` (this is the case on GitHub Actions runners).
#
# Release assets expected for tag <v>:
#   nepomuk-<v>-<target>.tar.gz   containing `nepomuk` (`nepomuk.exe` on Windows)
#   SHA256SUMS                    `<sha256>  <asset>` lines
#   SHA256SUMS.sig                ssh-keygen -Y sign -n nepomuk-release -f <key> SHA256SUMS
# Targets: x86_64|aarch64-unknown-linux-musl, x86_64|aarch64-apple-darwin,
#          x86_64|aarch64-pc-windows-msvc

set -eu

REPO="aleslanik2/nepomuk"
NAMESPACE="nepomuk-release"

# Public keys allowed to sign releases (allowed_signers format: `<principal> <key type> <key>`).
RELEASE_SIGNERS='
release@nepomuk ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClyxfJb2+KHFDtD0JbFya1aAdTl7zrawzY7NA7cH2Uo
'

usage() {
    cat <<EOF
Usage: install.sh [options]

Options:
  --version <tag>     Release to install (default: latest; env NEPOMUK_VERSION)
  --dir <path>        Installation directory (default: ~/.local/bin; env NEPOMUK_INSTALL_DIR)
  --sha256 <hash>     Expected SHA-256 of the release archive (env NEPOMUK_SHA256)
  --signers <file>    allowed_signers file with release keys (default: keys in this script)
  --base-url <url>    Download from a mirror instead of GitHub releases (env NEPOMUK_BASE_URL)
  --from-source       Build with cargo from the git tag instead of downloading a binary
  -h, --help          Show this help
EOF
}

say() { printf 'nepomuk-install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }

VERSION="${NEPOMUK_VERSION:-latest}"
INSTALL_DIR="${NEPOMUK_INSTALL_DIR:-}"
EXPECTED_SHA="${NEPOMUK_SHA256:-}"
SIGNERS_FILE=""
BASE_URL="${NEPOMUK_BASE_URL:-}"
FROM_SOURCE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?}"; shift 2 ;;
        --dir) INSTALL_DIR="${2:?}"; shift 2 ;;
        --sha256) EXPECTED_SHA="${2:?}"; shift 2 ;;
        --signers) SIGNERS_FILE="${2:?}"; shift 2 ;;
        --base-url) BASE_URL="${2:?}"; shift 2 ;;
        --from-source) FROM_SOURCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

# ---------------------------------------------------------------- Platform

detect_target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch=x86_64 ;;
        arm64|aarch64) arch=aarch64 ;;
        *) die "unsupported architecture: $arch" ;;
    esac
    case "$os" in
        Linux) OS=linux; TARGET="$arch-unknown-linux-musl"; EXE=nepomuk ;;
        Darwin) OS=macos; TARGET="$arch-apple-darwin"; EXE=nepomuk ;;
        MINGW*|MSYS*|CYGWIN*) OS=windows; TARGET="$arch-pc-windows-msvc"; EXE=nepomuk.exe ;;
        *) die "unsupported operating system: $os (on Windows run this script in Git Bash)" ;;
    esac
}

default_dir() {
    if [ "$OS" = windows ] && [ -n "${LOCALAPPDATA:-}" ]; then
        if command -v cygpath >/dev/null 2>&1; then
            printf '%s/nepomuk/bin' "$(cygpath -u "$LOCALAPPDATA")"
        else
            printf '%s/nepomuk/bin' "$LOCALAPPDATA"
        fi
    else
        printf '%s/.local/bin' "${HOME:?HOME is not set}"
    fi
}

# ---------------------------------------------------------------- Tools

download() { # url dest
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https,file' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        die "curl or wget is required"
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | sed 's/.*= *//'
    else
        die "sha256sum, shasum or openssl is required"
    fi
}

lower() { printf '%s' "$1" | tr 'A-F' 'a-f'; }

use_gh() {
    [ -z "$BASE_URL" ] && [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ] && command -v gh >/dev/null 2>&1
}

fetch() { # asset-name
    if use_gh; then
        GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}" gh release download "$VERSION" -R "$REPO" -p "$1" -D "$WORK" --clobber
    else
        download "$base/$1" "$WORK/$1"
    fi
}

resolve_latest() {
    if use_gh; then
        GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}" gh release view -R "$REPO" --json tagName -q .tagName || die "no release found in $REPO"
        return
    fi
    # Follows the /releases/latest redirect instead of the rate-limited API.
    url="https://github.com/$REPO/releases/latest"
    if command -v curl >/dev/null 2>&1; then
        loc=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$url") || die "cannot reach GitHub"
    else
        loc=$(wget -q -S --spider "$url" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n1 | tr -d '\r')
    fi
    tag=${loc##*/}
    case "$tag" in
        ""|latest|releases) die "no release found in $REPO" ;;
    esac
    printf '%s' "$tag"
}

# ---------------------------------------------------------------- Install

install_binary() { # source-file
    mkdir -p "$INSTALL_DIR"
    tmp_bin="$INSTALL_DIR/.$EXE.tmp.$$"
    cp "$1" "$tmp_bin"
    chmod 755 "$tmp_bin"
    mv -f "$tmp_bin" "$INSTALL_DIR/$EXE"
}

from_source() {
    command -v cargo >/dev/null 2>&1 || die "cargo is required for --from-source (https://rustup.rs)"
    say "building $VERSION from source with cargo"
    if [ "$VERSION" = latest ]; then
        set -- --branch main
    else
        set -- --tag "$VERSION"
    fi
    cargo install --locked --git "https://github.com/$REPO" "$@" --root "$WORK/root" nepomuk
    install_binary "$WORK/root/bin/$EXE"
}

from_release() {
    [ "$VERSION" = latest ] && VERSION=$(resolve_latest)
    asset="nepomuk-$VERSION-$TARGET.tar.gz"
    base="${BASE_URL:-https://github.com/$REPO/releases/download/$VERSION}"
    say "downloading $asset"
    fetch "$asset" || die "download failed: $asset"
    actual=$(lower "$(sha256_of "$WORK/$asset")")

    if [ -n "$EXPECTED_SHA" ]; then
        # A pinned hash is the trust anchor; nothing else is needed.
        [ "$actual" = "$(lower "$EXPECTED_SHA")" ] || die "SHA-256 mismatch: expected $EXPECTED_SHA, got $actual"
        say "SHA-256 matches the pinned value"
    else
        fetch SHA256SUMS || die "download failed: SHA256SUMS"
        fetch SHA256SUMS.sig || die "download failed: SHA256SUMS.sig (is the release signed?)"
        if [ -n "$SIGNERS_FILE" ]; then
            cp "$SIGNERS_FILE" "$WORK/allowed_signers"
        else
            printf '%s' "$RELEASE_SIGNERS" | sed '/^[[:space:]]*$/d' >"$WORK/allowed_signers"
        fi
        [ -s "$WORK/allowed_signers" ] || die "no release signing key configured; pin the archive hash with --sha256"
        command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen (OpenSSH 8.1+) is required to verify the signature; or pin --sha256"
        principal=$(sed -n '1{s/[[:space:]].*//;p;}' "$WORK/allowed_signers")
        if ! ssh-keygen -Y verify -f "$WORK/allowed_signers" -I "$principal" -n "$NAMESPACE" \
            -s "$WORK/SHA256SUMS.sig" <"$WORK/SHA256SUMS" >/dev/null 2>&1; then
            die "invalid signature on SHA256SUMS"
        fi
        expected=$(awk -v a="$asset" '$2 == a || $2 == "*"a { print $1 }' "$WORK/SHA256SUMS")
        [ -n "$expected" ] || die "$asset is not listed in SHA256SUMS"
        [ "$actual" = "$(lower "$expected")" ] || die "SHA-256 mismatch for $asset"
        say "signature and SHA-256 verified"
    fi

    mkdir "$WORK/x"
    tar -xzf "$WORK/$asset" -C "$WORK/x"
    bin=$(find "$WORK/x" -type f -name "$EXE" | head -n1)
    [ -n "$bin" ] || die "$EXE not found in $asset"
    install_binary "$bin"
}

detect_target
[ -n "$INSTALL_DIR" ] || INSTALL_DIR=$(default_dir)

WORK=$(mktemp -d 2>/dev/null || mktemp -d -t nepomuk-install)
trap 'rm -rf "$WORK"' EXIT INT TERM

if [ "$FROM_SOURCE" = 1 ]; then
    from_source
else
    from_release
fi

installed="$INSTALL_DIR/$EXE"
"$installed" version >/dev/null 2>&1 || die "the installed binary does not run: $installed"
say "installed $("$installed" version | head -n1) to $installed"

# Make it available to the following steps of a CI job.
if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "$INSTALL_DIR" >>"$GITHUB_PATH"
fi
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) [ -n "${GITHUB_PATH:-}" ] || say "note: $INSTALL_DIR is not in PATH; add it to your shell profile" ;;
esac
