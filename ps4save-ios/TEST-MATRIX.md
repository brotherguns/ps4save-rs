# ps4save-ios — device test (box flow, single install)

**Install just one ipa now: `PS4SaveTool.ipa` (16:35).**

It carries the **file-boxes flow as first choice**: Encrypt → Browse →
**"File boxes: pick files, rebuild folder (works everywhere)"**. File
multi-picks with copy semantics are the one pipeline already proven
working on feather-installed apps — the folder Open-grant path was the
only thing stalling. Two slots:

- **save files** → every file of the save root (multi-select, repeatable)
- **sce_sys files** → its contents, **must include param.sfo**
  (Build is refused without it)

Long-press a box to clear it. "Build & use" assembles
`Documents/imports/rebuild-<uuid>/{files, sce_sys/}` — a normal tree the
core encrypts exactly like a picked folder — and commits it as the input
path. If Open works there too, bonus; folder pickers stay in the alert
(legacy Import routing default-on) as alternates.

## If the folder Open is still wanted (or a pick misbehaves)

Step 0 costs **zero builds**: the upstream thread (Feather #610) documents
the same IPA choosing **differently by signer** — folder-add sick under
Feather, healthy under Sideloadly with the identical file. If you have any
PC/second signer available, the *very same* ipa there tells you whether
the disease is host-side in one move.

Then the instrumentation, in order:

1. `DocPickerProbe.ipa` — env dump + four-button callback log
2. the A/B/C/D/E plist matrix below (all share one byte-identical
   binary, sha256 `c6f98b07…`; every difference is plist-only)

Goal of the test: the **system folder picker** (Encrypt → Browse → pick a
folder → descend → Open). Prior failure shape: Open inert — no dismiss,
no callback, every location, both modes.

### 2. DocPickerProbe.ipa  (com.brotherguns.docpickerprobe)
Instrument, not a candidate. On launch it prints an **ENV DUMP** — what its
Info.plist looks like *after Feather signed it*. Then four buttons:

- folder — Open (in place)
- folder — Copy
- file — Open (in place)
- file — Copy

Every delegate callback is logged live on screen. Report:

- the ENV DUMP lines (scene manifest / LSSupportsOpeningDocumentsInPlace /
  UISupportsDocumentBrowser / UIFileSharingEnabled / CFBundleDocumentTypes
  entries — present or ABSENT)
- per button: whether the picker UI opened at all, and whether a log line
  appeared after choosing (PICKED/urls…) or CANCELLED

### 3. The plist matrix (only while D is dead)
- `PS4SaveTool.ipa`  (A) — scene lifecycle + CFBundleDocumentTypes
- `PS4SaveToolB.ipa` (B) — A + UISupportsDocumentBrowser
- `PS4SaveToolC.ipa` (C) — B minus scene-manifest (classic lifecycle)
- `PS4SaveToolD.ipa` (D) — the legacy-Import routing (see §1)
- `PS4SaveToolE.ipa` (E) — D + UISupportsDocumentBrowser (stacked hypotheses)

**all five PS4SaveTool ipas share one byte-identical binary** (sha256
`c6f98b07…`) — every behavioral difference lives in Info.plist only,
so each install tests exactly one variable.

Error shape per app is what matters: inert-Open-with-silence vs crash vs
picker-opened-but-no-callback.

## Status

- Release workflow **frozen** — nothing pushed, nothing published until the
  device test confirms the fix.
- Winner's fix gets merged into `app/App.m` + the main plist first, then
  committed/pushed per the goal's release gate.
