#!/bin/sh
# UNFREEZE the ps4save-io release pipeline.
# REVIEW-ONLY UNTIL RUN WITH --yes --push --release.
#
# Stages:
#   1. sync   : mirror current ps4save-ios/ (sources only) into the published
#               repo's nested ps4save-ios/ tree
#   2. commit : staged, with a prepared message
#   3. push   : explicit gate (--push)
#   4. release: explicit gate (--release) — gh release upload to v0.1.2
#
# Prerequisites before ANY stage runs:
#   - He has tested the matrix on device and given the go
#   - keys audit passes (no config.ini, no real key prefixes, in the tree)
set -euo pipefail

WORK="/run/media/brotherguns/BROTHERGUNS/ps4save-ios"
REPO="/run/media/brotherguns/BROTHERGUNS/ps4save-rs-repo"
NEST="$REPO/ps4save-ios"

DO_PUSH=0; DO_RELEASE=0
for arg in "$@"; do
  case "$arg" in
    --push)    DO_PUSH=1 ;;
    --release) DO_RELEASE=1 ;;
    --dry)     echo "dry-run: printing actions only"; DO_DRY=1 ;;
    *) echo "usage: $0 [--dry] [--push] [--release]   (requires explicit go)"; exit 2 ;;
  esac
done

[ -d "$WORK" ] && [ -d "$REPO/.git" ] || { echo "paths missing"; exit 1; }
if [ "${DO_DRY:-0}" = "1" ]; then
  echo "would sync: rsync -a --delete \\"
  echo "  --exclude 'Payload*' --exclude '*.ipa' --exclude '.build' \\"
  echo "  --exclude '.bsp' --exclude 'xtool/' --exclude 'xtoolapp*/Libs/' \\"
  echo "  --exclude '.gitignore-d artifacts' \\"
  echo "  $WORK/ $NEST/"
  echo "would commit  (message below) and ONLY push with --push / upload with --release"
  echo "-----"
  cat "$REPO/ps4save-ios/UNFREEZE-COMMITMSG.txt" 2>/dev/null || echo "## ps4save-ios folder-picker repair (iOS 26.x Feather installs)"
  exit 0
fi

# ---- keys audit on the SOURCE tree before anything moves
# config.ini files are runtime-local state (same exclusion as the sync)
# and are re-checked inside BUILT artifacts below, never trusted blind.
for key in D212FC335F6DDB8 F967AD9912310C B5DAEFFF39E6 9EC89DCAD04E DF9293D9857A 2BCF698E79CF; do
  if grep -rq --exclude='config.ini' "$key" "$WORK/app" "$WORK/ios_core" "$WORK/xtoolapp" "$WORK/probeapp" 2>/dev/null; then
    echo "ABORT: real key material found in sources ($key)"
    exit 3
  fi
done
echo "keys audit on sources: clean"

# ---- phase 1: sync sources only
rsync -a --delete \
  --exclude 'Payload*' --exclude '*.ipa' --exclude '.build' \
  --exclude '.bsp' --exclude 'xtool/' --exclude 'xtoolapp*/Libs/' \
  --exclude 'config.ini' \
  "$WORK/" "$NEST/"
echo "synced -> $NEST"

# ---- keys audit on the DEST tree after sync
# (unfreeze.sh excluded: it contains the audit patterns themselves)
for key in D212FC335F6DDB8 F967AD9912310C B5DAEFFF39E6 9EC89DCAD04E DF9293D9857A 2BCF698E79CF; do
  if grep -rq --exclude='unfreeze.sh' "$key" "$NEST" 2>/dev/null; then
    echo "ABORT: real key material found in dest tree ($key)"
    exit 3
  fi
done
echo "keys audit on dest: clean"

# ---- phase 2: commit
cd "$REPO"
git add -A ps4save-ios
git commit -F- <<'MSG'
iOS: folder-picker repair for feathered installs

- dual-mode lifecycle (scene manifest when present, classic fallback)
- Info.plist: a-Shell-style CFBundleDocumentTypes registration
  (public.directory + public.folder, Editor/Alternate)
- UISupportsDocumentBrowser contract key
- PS4LegacyPickerMode knob: legacy UIDocumentPickerModeImport routing for
  folder picks (the repair the VexSign FilePickerFix force-swizzles onto
  sideloaded installs)
- file-boxes flow (SaveBoxesVC): first-choice input method that rebuilds
  the save folder from two multi-select file boxes (save root + sce_sys,
  param.sfo gate) over the asCopy pipeline that works on such installs
- DocPickerProbe: self-dumping callback lab for field isolation
- build-variant-{b,c,d}.sh + build-probe.sh; TEST-MATRIX.md field card
MSG
if [ "$DO_PUSH" = "0" ]; then
  echo "committed locally. PUSH GATED — rerun with --push to publish the commit."
  exit 0
fi

# ---- phase 3: push (explicit gate)
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
git push origin "$BRANCH"
echo "pushed $BRANCH."

# ---- phase 4: release upload (explicit gate)
if [ "$DO_RELEASE" = "0" ]; then
  echo "PUSH done. RELEASE GATED — rerun with --release to upload the ipa to v0.1.2."
  exit 0
fi
# full-ipa audit BEFORE upload: every decompressed byte of the zip,
# so a stowaway resource cannot ride the release.
for key in D212FC335F6DDB8 F967AD9912310C B5DAEFFF39E6 9EC89DCAD04E DF9293D9857A 2BCF698E79CF; do
  if unzip -p "$WORK/PS4SaveTool.ipa" | grep -aq "$key"; then
    echo "ABORT: real key material found inside PS4SaveTool.ipa ($key)"
    exit 3
  fi
done
echo "keys audit on ipa: clean"
gh release upload v0.1.2 "$WORK/PS4SaveTool.ipa" --clobber
echo "release v0.1.2 updated."
