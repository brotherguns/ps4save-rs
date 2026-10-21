#!/bin/sh
# Build the PS4SaveTool C variant: a-Shell-style plist WITHOUT a scene
# manifest; the shared App.m falls back to the classic window path.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
XAPP="$HERE/xtoolappC"
MAINAPP="$HERE/xtoolapp"

export PATH="/mnt/iosdev/swift/usr/bin:$HOME/.cargo/bin:$PATH"
command -v xtool >/dev/null || { echo "error: xtool missing"; exit 1; }

[ -s "$MAINAPP/Libs/App.o" ] || { echo "error: stage main Libs first (run build.sh)"; exit 1; }
[ -s "$MAINAPP/Libs/libps4save_ios_core.a" ] || { echo "error: rust core missing"; exit 1; }

for f in Package.swift xtool.yml Support/Info.plist; do [ -f "$XAPP/$f" ] || { echo "error: missing $f"; exit 1; }; done
[ -f "$XAPP/Sources/PS4SaveAppC/PS4SaveTool.swift" ] || { echo "error: missing entry swift"; exit 1; }

cp "$HERE/../config.example.ini" "$XAPP/Sources/PS4SaveAppC/config.ini"

echo "==> xtool dev build (variant C)..."
(cd "$XAPP" && xtool dev build -c release)

echo "==> packaging ipa..."
mkdir -p "$HERE/PayloadC"
rm -rf "$HERE/PayloadC/PS4SaveToolC.app" 2>/dev/null
cp -r "$XAPP/xtool/PS4SaveToolC.app" "$HERE/PayloadC/"

(cd "$HERE" && rm -f PS4SaveToolC.ipa && zip -qr PS4SaveToolC.ipa PayloadC)

echo ""
echo "built: $HERE/PS4SaveToolC.ipa"
echo "app:   $HERE/PayloadC/PS4SaveToolC.app"
