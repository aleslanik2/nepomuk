#!/bin/sh
# nepomuk installer for Linux, macOS and Windows (Git Bash / MSYS2 / Cygwin).
#
#   curl -fsSL https://raw.githubusercontent.com/aleslanik2/nepomuk/main/install.sh | sh
#   sh install.sh --version v0.1.0 --dir /usr/local/bin
#   sh install.sh --system                           # the CLI for all users (/usr/local/bin, sudo)
#   sh install.sh --gui --system                     # the CLI and the desktop app, for all users
#   sh install.sh --gui --from-source --source .     # build the app from a local checkout
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
#   nepomuk-gui-<v>-<target>.dmg | .AppImage | .exe   the desktop app (--gui)
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
  --system            Install for all users: /usr/local/bin (Windows: Program Files\nepomuk),
                      using sudo when needed; with --gui the system-wide app locations
  --sha256 <hash>     Expected SHA-256 of the release archive (env NEPOMUK_SHA256)
  --signers <file>    allowed_signers file with release keys (default: keys in this script)
  --base-url <url>    Download from a mirror instead of GitHub releases (env NEPOMUK_BASE_URL)
  --from-source       Build from source (cargo; for --gui also Node.js) instead of downloading
  --source <dir>      Local checkout to build from (default: clone the git tag)
  --gui               Also install the desktop app (macOS: Applications, Linux: AppImage, Windows: installer)
  --app-dir <path>    Where to put nepomuk.app on macOS (default: /Applications or ~/Applications)
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
SOURCE_DIR=""
GUI=0
APP_DIR=""
SYSTEM=0
SUDO=""

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?}"; shift 2 ;;
        --dir) INSTALL_DIR="${2:?}"; shift 2 ;;
        --sha256) EXPECTED_SHA="${2:?}"; shift 2 ;;
        --signers) SIGNERS_FILE="${2:?}"; shift 2 ;;
        --base-url) BASE_URL="${2:?}"; shift 2 ;;
        --from-source) FROM_SOURCE=1; shift ;;
        --source) SOURCE_DIR="${2:?}"; shift 2 ;;
        --gui) GUI=1; shift ;;
        --app-dir) APP_DIR="${2:?}"; shift 2 ;;
        --system) SYSTEM=1; shift ;;
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
    if [ "$SYSTEM" = 1 ]; then
        if [ "$OS" = windows ]; then
            pf="${PROGRAMFILES:-C:\\Program Files}"
            if command -v cygpath >/dev/null 2>&1; then pf=$(cygpath -u "$pf"); fi
            printf '%s/nepomuk' "$pf"
        else
            printf '/usr/local/bin'
        fi
    elif [ "$OS" = windows ] && [ -n "${LOCALAPPDATA:-}" ]; then
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

# Privileged steps are collected in $WORK/priv.sh and run with one elevation at the end:
# sudo in a terminal (or NEPOMUK_SUDO, e.g. doas), the system administrator dialog on macOS
# without a terminal (it accepts Touch ID; the password never passes through this script).
PRIV=0

has_tty() {
    [ -t 0 ] || { [ -r /dev/tty ] && (: </dev/tty) 2>/dev/null; }
}

choose_sudo() { # directory
    d="$1"
    while [ ! -d "$d" ]; do d=$(dirname "$d"); done
    if [ -w "$d" ] || [ "$(id -u 2>/dev/null || echo 0)" = 0 ]; then
        PRIV=0
        return
    fi
    [ "$OS" != windows ] || die "$1 needs administrator rights: run Git Bash as administrator"
    PRIV=1
    if [ -n "$SUDO" ]; then return; fi
    if [ -n "${NEPOMUK_SUDO:-}" ] || has_tty; then
        SUDO="${NEPOMUK_SUDO:-sudo}"
        command -v "$SUDO" >/dev/null 2>&1 || die "$1 is not writable and $SUDO is not available"
        say "installing into $1 needs administrator rights; using $SUDO"
    elif [ "$OS" = macos ] && command -v osascript >/dev/null 2>&1; then
        SUDO=osascript
        say "installing into $1 needs administrator rights; macOS will ask for them"
    else
        die "$1 needs administrator rights: run this in a terminal (sudo needs one to ask for the password)"
    fi
}

# Runs a command now, or queues it when the current target needs administrator rights.
priv() {
    if [ "$PRIV" = 0 ]; then
        "$@"
        return
    fi
    line=""
    for arg in "$@"; do
        line="$line '$(printf '%s' "$arg" | sed "s/'/'\\\\''/g")'"
    done
    printf '%s\n' "$line" >>"$WORK/priv.sh"
}

flush_priv() {
    [ -s "$WORK/priv.sh" ] || return 0
    if [ "$SUDO" = osascript ]; then
        osascript -e 'on run argv' \
            -e 'do shell script "/bin/sh -e " & quoted form of (item 1 of argv) with prompt (item 2 of argv) with administrator privileges' \
            -e 'end run' "$WORK/priv.sh" "The nepomuk installer needs administrator rights to install for all users." \
            >/dev/null || die "administrator rights were not granted"
    else
        $SUDO sh -e "$WORK/priv.sh" || die "the privileged installation steps failed"
    fi
    : >"$WORK/priv.sh"
}

put_file() { # source dir name
    priv mkdir -p "$2"
    priv cp "$1" "$2/.$3.tmp.$$"
    priv chmod 755 "$2/.$3.tmp.$$"
    priv mv -f "$2/.$3.tmp.$$" "$2/$3"
}

install_binary() { # source-file
    choose_sudo "$INSTALL_DIR"
    put_file "$1" "$INSTALL_DIR" "$EXE"
}

from_source() {
    command -v cargo >/dev/null 2>&1 || die "cargo is required for --from-source (https://rustup.rs)"
    say "building $VERSION from source with cargo"
    if [ "$VERSION" = latest ]; then
        set -- --branch main
    else
        set -- --tag "$VERSION"
    fi
    if [ -n "$SOURCE_DIR" ]; then
        cargo install --locked --path "$SOURCE_DIR" --root "$WORK/root"
    else
        cargo install --locked --git "https://github.com/$REPO" "$@" --root "$WORK/root" nepomuk
    fi
    install_binary "$WORK/root/bin/$EXE"
}

# Downloads a release asset and verifies it (pinned hash, or signed SHA256SUMS).
download_verified() { # asset
    asset="$1"
    [ "$VERSION" = latest ] && VERSION=$(resolve_latest)
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
}

from_release() {
    [ "$VERSION" = latest ] && VERSION=$(resolve_latest)
    asset="nepomuk-$VERSION-$TARGET.tar.gz"
    download_verified "$asset"
    mkdir "$WORK/x"
    tar -xzf "$WORK/$asset" -C "$WORK/x"
    bin=$(find "$WORK/x" -type f -name "$EXE" | head -n1)
    [ -n "$bin" ] || die "$EXE not found in $asset"
    install_binary "$bin"
    helper=$(find "$WORK/x" -type f -name nepomuk-touchid | head -n1)
    if [ -n "$helper" ]; then
        put_file "$helper" "$INSTALL_DIR" nepomuk-touchid
    fi
}

# ---------------------------------------------------------------- Desktop app

gui_target() {
    case "$OS" in
        macos) GUI_TARGET="$TARGET"; GUI_EXT=dmg ;;
        linux)
            [ "${TARGET%%-*}" = x86_64 ] || die "the desktop app is built for x86_64 Linux only"
            GUI_TARGET=x86_64-unknown-linux-gnu; GUI_EXT=AppImage ;;
        # ARM64 Windows runs the x86_64 app through emulation.
        windows) GUI_TARGET=x86_64-pc-windows-msvc; GUI_EXT=exe ;;
    esac
}

install_app_macos() { # path to nepomuk.app
    if [ -z "$APP_DIR" ]; then
        if [ "$SYSTEM" = 1 ] || [ -w /Applications ]; then APP_DIR=/Applications; else APP_DIR="$HOME/Applications"; fi
    fi
    # Staged first: the disk image is detached before the privileged steps run.
    mkdir -p "$WORK/stage"
    cp -R "$1" "$WORK/stage/nepomuk.app"
    choose_sudo "$APP_DIR"
    priv mkdir -p "$APP_DIR"
    if pgrep -f "$APP_DIR/nepomuk.app/Contents/MacOS/nepomuk-gui" >/dev/null 2>&1; then
        say "quitting the running app"
        pkill -f "$APP_DIR/nepomuk.app/Contents/MacOS/nepomuk-gui" || true
        sleep 1
    fi
    priv rm -rf "$APP_DIR/nepomuk.app.tmp.$$"
    priv cp -R "$WORK/stage/nepomuk.app" "$APP_DIR/nepomuk.app.tmp.$$"
    priv rm -rf "$APP_DIR/nepomuk.app"
    priv mv "$APP_DIR/nepomuk.app.tmp.$$" "$APP_DIR/nepomuk.app"
    # Verified above; a copy made by this script carries no quarantine flag.
    priv xattr -cr "$APP_DIR/nepomuk.app"
    GUI_INSTALLED="$APP_DIR/nepomuk.app"
}

install_app_linux() { # path to the AppImage
    choose_sudo "$INSTALL_DIR"
    put_file "$1" "$INSTALL_DIR" nepomuk-gui
    if [ "$SYSTEM" = 1 ]; then
        apps=/usr/share/applications
    else
        apps="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
    fi
    cat >"$WORK/nepomuk.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=nepomuk
Comment=Post-quantum secrets vault
Exec=$INSTALL_DIR/nepomuk-gui
Terminal=false
Categories=Utility;Security;
DESKTOP
    choose_sudo "$apps"
    priv mkdir -p "$apps"
    priv cp "$WORK/nepomuk.desktop" "$apps/nepomuk.desktop"
    GUI_INSTALLED="$INSTALL_DIR/nepomuk-gui"
}

install_app_windows() { # path to the NSIS installer
    say "running the installer"
    "$1" /S || die "the installer failed"
    GUI_INSTALLED="the Start menu (nepomuk)"
}

gui_from_release() {
    gui_target
    [ "$VERSION" = latest ] && VERSION=$(resolve_latest)
    asset="nepomuk-gui-$VERSION-$GUI_TARGET.$GUI_EXT"
    download_verified "$asset"
    case "$OS" in
        macos)
            mnt="$WORK/mnt"
            mkdir "$mnt"
            # The image shows the Apache 2.0 license; accept it non-interactively.
            # (-quiet would decline it).
            yes | PAGER=cat hdiutil attach -nobrowse -readonly -mountpoint "$mnt" "$WORK/$asset" >/dev/null 2>&1 ||
                die "cannot open $asset"
            app=$(find "$mnt" -maxdepth 1 -name "*.app" | head -n1)
            [ -n "$app" ] || { hdiutil detach -quiet "$mnt"; die "no app in $asset"; }
            install_app_macos "$app"
            hdiutil detach -quiet "$mnt" || true
            ;;
        linux) install_app_linux "$WORK/$asset" ;;
        windows) install_app_windows "$WORK/$asset" ;;
    esac
}

gui_from_source() {
    gui_target
    command -v cargo >/dev/null 2>&1 || die "cargo is required (https://rustup.rs)"
    command -v npx >/dev/null 2>&1 || die "Node.js (npx) is required to run the Tauri CLI"
    if [ -n "$SOURCE_DIR" ]; then
        src=$(cd "$SOURCE_DIR" && pwd)
    else
        src="$WORK/src"
        ref=main; [ "$VERSION" = latest ] || ref="$VERSION"
        say "cloning $REPO ($ref)"
        git clone -q --depth 1 --branch "$ref" "https://github.com/$REPO.git" "$src" || die "cannot clone $REPO"
    fi
    [ -f "$src/gui/src-tauri/tauri.conf.json" ] || die "$src is not a nepomuk checkout"
    case "$OS" in
        macos) bundles=app ;;
        linux) bundles=appimage ;;
        windows) bundles=nsis ;;
    esac
    say "building the desktop app in $src (this takes a few minutes)"
    "$src/gui/scripts/prepare-sidecars.sh" "$GUI_TARGET" >&2
    (cd "$src/gui/src-tauri" && npx --yes @tauri-apps/cli@2.12.0 build --target "$GUI_TARGET" --bundles "$bundles" >&2) || die "the build failed"
    b="$src/gui/src-tauri/target/$GUI_TARGET/release/bundle"
    case "$OS" in
        macos) install_app_macos "$b/macos/nepomuk.app" ;;
        linux) install_app_linux "$(find "$b/appimage" -name '*.AppImage' | head -n1)" ;;
        windows) install_app_windows "$(find "$b/nsis" -name '*.exe' | head -n1)" ;;
    esac
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

# The desktop app comes in addition to the CLI.
if [ "$GUI" = 1 ]; then
    if [ "$FROM_SOURCE" = 1 ]; then gui_from_source; else gui_from_release; fi
fi

# One elevation for everything that needs administrator rights.
flush_priv

installed="$INSTALL_DIR/$EXE"
"$installed" version >/dev/null 2>&1 || die "the installed binary does not run: $installed"
say "installed $("$installed" version | head -n1) to $installed"

# Make it available to the following steps of a CI job.
if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "$INSTALL_DIR" >>"$GITHUB_PATH"
fi
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        if [ -z "${GITHUB_PATH:-}" ]; then
            if [ "$OS" = windows ] && [ "$SYSTEM" = 1 ]; then
                say "note: add $INSTALL_DIR to the system PATH (or use install.ps1 -System, which does it)"
            else
                say "note: $INSTALL_DIR is not in PATH; add it to your shell profile"
            fi
        fi
        ;;
esac

if [ "$GUI" = 1 ]; then
    say "installed the nepomuk desktop app to $GUI_INSTALLED"
    if [ "$OS" = macos ]; then say "start it from Launchpad or with: open \"$GUI_INSTALLED\""; fi
fi
