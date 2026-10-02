#!/bin/sh
# Builds the CLI (and on macOS the Touch ID helper) and places them where Tauri bundles
# external binaries: gui/src-tauri/binaries/<name>-<target triple>.
#
#   gui/scripts/prepare-sidecars.sh [target-triple]

set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
target="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
bin="$root/gui/src-tauri/binaries"
mkdir -p "$bin"

exe=""
case "$target" in *windows*) exe=".exe" ;; esac

if [ -z "${NEPOMUK_SKIP_CLI_BUILD:-}" ]; then
    cargo build --release --locked --manifest-path "$root/Cargo.toml" --target "$target"
fi
cp "$root/target/$target/release/nepomuk$exe" "$bin/nepomuk-$target$exe"

case "$target" in
    *apple-darwin)
        arch=${target%%-*}
        [ "$arch" = aarch64 ] && arch=arm64
        INFO_PLIST="$root/macos/touchid/Info.plist"
        # The embedded Info.plist names the app "nepomuk" in the Touch ID prompt.
        xcrun swiftc -O -target "$arch-apple-macos11" -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker "$INFO_PLIST" -o "$bin/nepomuk-touchid-$target" "$root/macos/touchid/main.swift"
        ;;
esac
ls -l "$bin"
