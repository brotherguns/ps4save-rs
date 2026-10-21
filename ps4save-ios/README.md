# PS4 Save Tool — iOS build

Native iOS port: the desktop `egui` GUI replaced by a UIKit app, driven by the
same `ps4save-rs` core (crypto, PFS, sealed keys — untouched).

## Layout
- `ios_core/`   — rust `staticlib` shim (C ABI) wrapping the core commands.
- `app/App.m`   — the whole UIKit app (tabs, file picker, ANSI output view).
- `app/Info.plist`
- `build.sh`    — cross-compile + link + package into an unsigned ipa.
- `../config.ini` — bundled into the app; copied to Documents on first launch.

## Requirements (linux toolchain)
- rustup target: `rustup target add aarch64-apple-ios`
- clang that targets iOS (`-target arm64-apple-ios15.0`) + the iOS SDK
  (defaults to `../iPhoneOS16.5.sdk`, override with `SDK=/path`)
- `ldid` (fake-signing) and `zip`

## Build

```sh
SDK=../iPhoneOS16.5.sdk ./build.sh
```

Produces `ps4save-ios/PS4SaveTool.ipa`.

## Install (unsigned)
Any of your usual routes — TrollStore, or sign with your own cert
(`unsigned` ldid-adhoc works there), or the jailed signer of choice.

## Using it
The app's sandbox `Documents` folder is the workspace. `UIFileSharingEnabled`
is on, so it shows up in the **Files app / Finder / iTunes file sharing**:

1. Drop a save (the `.bin` + image pair, or a whole save folder) into
   `PS4 Save Tool/Documents/` via Files / AirDrop / iTunes.
2. Tabs: **Decrypt / Encrypt / Resign / Reregion / Inspect / Utils** — same
   fields as the desktop GUI. `...` opens a Documents file picker. On first
   launch the bundled `config.ini` is copied to `Documents/config.ini`; you
   can edit/replace it there (Utils tab shows the resolved key count).
3. Outputs stay in Documents (pull them back out through Files).

Notes:
- `workdir/` and relative outputs are anchored to Documents automatically.
- keystone / list run from the **Utils** tab; check-config + selftest too.
- ANSI colors from the core output are rendered with the same palette as the
  desktop GUI (`ffcc66` accent etc).
