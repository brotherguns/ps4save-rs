# UNFREEZE — the go-live path for the folder-picker fix

Status: **frozen.** Nothing on this page has been executed. The script
(`unfreeze.sh`) is staged but refuses to publish anything without explicit
flags, and nothing runs at all until the device test comes back confirmed.

## Where we actually stand

Working sources live in `ps4save-ios/` (not git-tracked). The published
GitHub repo is `ps4save-rs-repo/` and carries an **older-generation** nested
copy of `ps4save-ios/` (no `xtoolapp/` packaging yet, App.m differs). So the
finalization is a tree-level sync, not a file patch — scripted, audited,
gated.

## Verdict branches (awaiting device test)

| Verdict | What happens |
|---|---|
| **D works** (legacy Import completes Open) | Root cause confirmed: modern Open-in-place grant path stalls on feathered installs. `PS4LegacyPickerMode=true` would be appended to the main `xtoolapp/Support/Info.plist`, main ipa rebuilt + audited, then unfreeze. |
| **D dead, probe P shows keys present + silent callbacks** | Grant-stall at a deeper layer; P's dump + callback log dictates next probe. No unfreeze. |
| **A/B/C win instead** | The winning plist combo gets baked into the main app the same way. Then unfreeze. |

## The scripted path (staged, not run)

```
./unfreeze.sh --dry              # review actions only — safe
./unfreeze.sh                    # sync + LOCAL commit only; push gated
./unfreeze.sh --push             # also pushes the commit
./unfreeze.sh --push --release   # also uploads the (winning) ipa to v0.1.2
```

Built-in gates:
- keys audit runs before sync and after sync (six real key prefixes from
  `config.ini`; aborts on any hit)
- `config.ini` itself is excluded from the sync — only the keyless
  `config.example.ini` rides
- artifact exclusions: `Payload*`, `*.ipa`, `.build`, `.bsp`, `xtool/`,
  `xtoolapp*/Libs/`
- explicit flags required for push and for `gh release upload --clobber`

## Prepared commit message

```
iOS: folder-picker repair for feathered installs

- dual-mode lifecycle (scene manifest when present, classic fallback)
- Info.plist: a-Shell-style CFBundleDocumentTypes registration
  (public.directory + public.folder, Editor/Alternate)
- UISupportsDocumentBrowser contract key
- PS4LegacyPickerMode knob: legacy UIDocumentPickerModeImport routing for
  folder picks (the repair the VexSign FilePickerFix force-swizzles onto
  sideloaded installs)
- DocPickerProbe: self-dumping callback lab for field isolation
- build-variant-{b,c,d}.sh + build-probe.sh; TEST-MATRIX.md field card
```

## Release target

`v0.1.2` currently hosts the broken ipa. After confirmation the winner is
uploaded with `gh release upload v0.1.2 <winner.ipa> --clobber` and the
stale body replaced — both commands are ready in `v0.1.2-notes.md`
(notes text + `gh release edit v0.1.2 --notes-file` one-liner).

## Optional pre-bump (He's call, at unfreeze time)

If the fix should ship as its own version instead of an asset replacement,
before running unfreeze:

1. bump `CFBundleShortVersionString` → `0.1.3` and `CFBundleVersion` → `3`
   in `xtoolapp/Support/Info.plist`
2. rebuild: `SDK=../iPhoneOS16.5.sdk ./build.sh`, re-audit keys
3. publish a new tag + release body alongside the merge

Both paths are compatible with the unfreeze script; the bump is two plist
lines + one rebuild.
