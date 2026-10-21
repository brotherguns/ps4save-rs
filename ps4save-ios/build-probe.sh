#!/bin/sh
# Build DocPickerProbe: four-picker logging lab that also dumps its own
# post-sign Info.plist values on launch. Pure Swift, no rust/ObjC artifacts.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
XAPP="$HERE/probeapp"

export PATH="/mnt/iosdev/swift/usr/bin:$HOME/.cargo/bin:$PATH"
command -v xtool >/dev/null || { echo "error: xtool missing"; exit 1; }

for f in Package.swift xtool.yml Support/Info.plist; do [ -f "$XAPP/$f" ] || { echo "error: missing $f"; exit 1; }; done
[ -f "$XAPP/Sources/DocPickerProbe/Probe.swift" ] || { echo "error: missing Probe.swift"; exit 1; }

echo "==> xtool dev build (probe)..."
(cd "$XAPP" && xtool dev build -c release)

echo "==> packaging ipa..."
mkdir -p "$HERE/PayloadProbe"
rm -rf "$HERE/PayloadProbe/DocPickerProbe.app" 2>/dev/null
cp -r "$XAPP/xtool/DocPickerProbe.app" "$HERE/PayloadProbe/"

(cd "$HERE" && rm -f DocPickerProbe.ipa && zip -qr DocPickerProbe.ipa PayloadProbe)

echo ""
echo "built: $HERE/DocPickerProbe.ipa"
echo "app:   $HERE/PayloadProbe/DocPickerProbe.app"
