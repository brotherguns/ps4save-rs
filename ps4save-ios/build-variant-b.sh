#!/bin/sh
# Build the PS4SaveTool B variant: main app + UISupportsDocumentBrowser knob.
# Reuses the Libs (App.o + rust core .a) freshly staged by build.sh.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
XAPP="$HERE/xtoolappB"
MAINAPP="$HERE/xtoolapp"

export PATH="/mnt/iosdev/swift/usr/bin:$HOME/.cargo/bin:$PATH"
command -v xtool >/dev/null || { echo "error: xtool missing"; exit 1; }

[ -s "$MAINAPP/Libs/App.o" ] || { echo "error: stage main Libs first (run build.sh)"; exit 1; }
[ -s "$MAINAPP/Libs/libps4save_ios_core.a" ] || { echo "error: rust core missing"; exit 1; }

for f in Package.swift xtool.yml Support/Info.plist; do [ -f "$XAPP/$f" ] || { echo "error: missing $f"; exit 1; }; done
[ -f "$XAPP/Sources/PS4SaveAppB/PS4SaveTool.swift" ] || { echo "error: missing entry swift"; exit 1; }

cp "$HERE/../config.example.ini" "$XAPP/Sources/PS4SaveAppB/config.ini"

echo "==> xtool dev build (variant B)..."
(cd "$XAPP" && xtool dev build -c release)

echo "==> packaging ipa..."
mkdir -p "$HERE/PayloadB"
rm -rf "$HERE/PayloadB/PS4SaveToolB.app" 2>/dev/null
cp -r "$XAPP/xtool/PS4SaveToolB.app" "$HERE/PayloadB/"

(cd "$HERE" && rm -f PS4SaveToolB.ipa && zip -qr PS4SaveToolB.ipa PayloadB)

echo ""
echo "built: $HERE/PS4SaveToolB.ipa"
echo "app:   $HERE/PayloadB/PS4SaveToolB.app"
