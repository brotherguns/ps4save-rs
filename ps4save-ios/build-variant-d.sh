#!/bin/sh
# Build the PS4SaveTool D variant: same plist as A + PS4LegacyPickerMode,
# routing folder picks through the deprecated Import (pre-trust copy)
# pipeline -- the repair VexSign force-swizzles onto sideloaded apps.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
XAPP="$HERE/xtoolappD"
MAINAPP="$HERE/xtoolapp"

export PATH="/mnt/iosdev/swift/usr/bin:$HOME/.cargo/bin:$PATH"
command -v xtool >/dev/null || { echo "error: xtool missing"; exit 1; }

[ -s "$MAINAPP/Libs/App.o" ] || { echo "error: stage main Libs first (run build.sh)"; exit 1; }
[ -s "$MAINAPP/Libs/libps4save_ios_core.a" ] || { echo "error: rust core missing"; exit 1; }

for f in Package.swift xtool.yml Support/Info.plist; do [ -f "$XAPP/$f" ] || { echo "error: missing $f"; exit 1; }; done
[ -f "$XAPP/Sources/PS4SaveAppD/PS4SaveTool.swift" ] || { echo "error: missing entry swift"; exit 1; }

cp "$HERE/../config.example.ini" "$XAPP/Sources/PS4SaveAppD/config.ini"

echo "==> xtool dev build (variant D)..."
(cd "$XAPP" && xtool dev build -c release)

echo "==> packaging ipa..."
mkdir -p "$HERE/PayloadD"
rm -rf "$HERE/PayloadD/PS4SaveToolD.app" 2>/dev/null
cp -r "$XAPP/xtool/PS4SaveToolD.app" "$HERE/PayloadD/"

(cd "$HERE" && rm -f PS4SaveToolD.ipa && zip -qr PS4SaveToolD.ipa PayloadD)

echo ""
echo "built: $HERE/PS4SaveToolD.ipa"
echo "app:   $HERE/PayloadD/PS4SaveToolD.app"
