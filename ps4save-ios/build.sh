#!/bin/sh
# Build PS4 Save Tool for iOS with xtool (SwiftPM) + the rust core staticlib.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
XAPP="$HERE/xtoolapp"
SDK="${SDK:-$HERE/../iPhoneOS16.5.sdk}"

export PATH="/mnt/iosdev/swift/usr/bin:$HOME/.cargo/bin:$PATH"
command -v xtool >/dev/null || { echo "error: xtool missing"; exit 1; }
command -v swift >/dev/null || { echo "error: swift missing"; exit 1; }
command -v cargo >/dev/null || { echo "error: cargo missing"; exit 1; }

echo "==> [1/5] building rust core staticlib..."
export CARGO_TARGET_DIR="/tmp/opencode/ps4save-ios-target"
export RUSTFLAGS=""
if [ -d "$SDK" ]; then
    export SDKROOT="$(cd "$SDK" && pwd)"
    # SDK repackage is missing libc/libm/iconv tbd aliases; create local copies.
    [ -e "$SDK/usr/lib/libSystem.tbd" ] || cp "$SDK/usr/lib/libSystem.B.tbd" "$SDK/usr/lib/libSystem.tbd" 2>/dev/null || true
    [ -e "$SDK/usr/lib/libiconv.tbd" ] || cp "$SDK/usr/lib/libiconv.2.tbd" "$SDK/usr/lib/libiconv.tbd" 2>/dev/null || true
    # LLD22 needs modern macho args (clang-on-linux emits legacy ones): python shim.
    mkdir -p "$HERE/build"
    cat > "$HERE/build/ios-link.py" <<'EOF'
#!/usr/bin/env python3
"""Translates rustc's cc-style linker invocation into ld64.lld macho args."""
import os, re, subprocess, sys

args = sys.argv[1:]
sdk = os.environ.get("SDKROOT", "")
if not sdk or not os.path.isdir(sdk):
    sys.stderr.write("ios-link: SDKROOT not set\n")
    sys.exit(1)
m = re.search(r"(?:iPhoneOS|iPhoneSimulator)([0-9.]+?)(?:\.sdk)?/?$", os.path.basename(sdk.rstrip("/")))
platsdk = m.group(1) if m else "5.0"
if platsdk and "." not in platsdk:
    platsdk += ".0"

plat, pmin = "ios", "10.0"
cmd = ["-dynamic", "-arch", "arm64"]
if platsdk != "0.0":
    cmd += ["-platform_version", plat, pmin, platsdk]
cmd += ["-syslibroot", sdk, "-lSystem"]

dylib = False
i, n = 0, len(args)
while i < n:
    a = args[i]
    nxt = args[i + 1] if i + 1 < n else None
    if a == "-target":
        t = nxt or ""
        if "ios" in t:
            plat = "ios"
        elif "macos" in t:
            plat = "macos"
        else:
            plat = "driverkit"
        tail = t.rsplit(plat + "-", 1)
        if len(tail) == 2 and tail[1]:
            pmin = tail[1]
        i += 2
        continue
    if a == "-o":
        cmd += ["-o", nxt]
        i += 2
        continue
    if a in ("-dynamiclib", "-shared", "-Wl,-dylib"):
        dylib = True
        i += 1
        continue
    if a == "-Wl,-exported_symbols_list":
        path = nxt or ""
        cmd += ["-exported_symbols_list", path[4:] if path.startswith("-Wl,") else path]
        i += 2
        continue
    if a.startswith("-Wl,"):
        for w in a[4:].split(","):
            if w:
                cmd.append(w)
        i += 1
        continue
    if a in ("-nodefaultlibs", "-fuse-ld=lld", "-fuse-ld=ld64.lld", "-no-pie", "-pie"):
        i += 1
        continue
    if a in ("-lc", "-lm"):
        # libSystem covers libc/libm on apple targets
        i += 1
        continue
    if a.startswith("-l") or a.startswith("-L"):
        cmd.append(a)
        i += 1
        continue
    if a.endswith((".o", ".a", ".rlib", ".so", ".dylib")):
        cmd.append(a)
        i += 1
        continue
    i += 1

if dylib:
    cmd.insert(0, "-dylib")
r = subprocess.call(["/usr/bin/ld64.lld"] + cmd)
sys.exit(r)
EOF
    chmod +x "$HERE/build/ios-link.py"
    export CARGO_TARGET_AARCH64_APPLE_IOS_LINKER="$HERE/build/ios-link.py"
fi
(cd "$HERE/ios_core" && cargo build --release --target aarch64-apple-ios)

echo "==> [2/5] compiling objC UI module..."
mkdir -p "$XAPP/Libs" "$XAPP/Sources/PS4SaveApp"
# pure compile (no link); the swift product's linker settings ingest this .o
clang -c -target arm64-apple-ios16.0 -isysroot "$SDK" -fobjc-arc -O2 \
    "$HERE/app/App.m" -o "$XAPP/Libs/App.o" 2>&1 | grep -E "error|warning" || true
[ -s "$XAPP/Libs/App.o" ] || { echo "error: App.o compile failed"; exit 1; }
cp "$CARGO_TARGET_DIR/aarch64-apple-ios/release/libps4save_ios_core.a" "$XAPP/Libs/"
# bundle a KEYLESS template by default; ship your personal keys via
# BUNDLE_CONFIG=/path/to/your/config.ini (that ipa must stay private!)
BUNDLE_CONFIG="${BUNDLE_CONFIG:-$HERE/../config.example.ini}"
cp "$BUNDLE_CONFIG" "$XAPP/Sources/PS4SaveApp/config.ini" 
test -s "$XAPP/Sources/PS4SaveApp/config.ini" || {
    echo "error: no config template found at $BUNDLE_CONFIG"; exit 1;
}
test -f "$XAPP/Sources/PS4SaveApp/PS4SaveTool.swift" || {
    echo "error: missing Sources/PS4SaveApp/PS4SaveTool.swift"; exit 1;
}

echo "==> [3/5] xtool dev build (release)..."
(cd "$XAPP" && xtool dev build -c release)

echo "==> [4/5] packaging ipa..."
mkdir -p "$HERE/Payload"
rm -rf "$HERE/Payload/PS4SaveTool.app" 2>/dev/null
cp -r "$XAPP/xtool/PS4SaveTool.app" "$HERE/Payload/"

echo "==> [5/5] zipping..."
(cd "$HERE" && rm -f PS4SaveTool.ipa && zip -qr PS4SaveTool.ipa Payload)

echo ""
echo "built: $HERE/PS4SaveTool.ipa"
echo "app:   $HERE/Payload/PS4SaveTool.app"
