# NetLurker

**See which Windows processes are connecting out. Inspect the evidence behind the risk signals.**

[![Build](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml/badge.svg)](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Türkçe](README.tr.md) · [Build & test](#build--test) · [Data accuracy](docs/DATA-ACCURACY.md) · [Privacy](PRIVACY.md) · [Release checklist](docs/RELEASE-CHECKLIST.md)

NetLurker is an open-source network investigation tool. The Windows app brings socket
ownership, process details, IP enrichment, TLS inspection, and explainable heuristics into
one native window. You can investigate without an AI API key: local rules remain available.

**Release status: pre-release hardening.** CI artifacts are development builds, not signed,
reviewed public releases. See [Releases](https://github.com/thesyntax1/NetLurker/releases)
for published packages when available. Do not download old executables from source folders
or assume a green build proves every remote provider is working.

## Why try it?

- **Start with a process, not an IP spreadsheet.** Find an application, its open connections,
  signature information, destination, and observed traffic in one place.
- **Ask why a signal fired.** Review the individual rules and supporting lookups rather
  than accepting an unexplained red badge.
- **Keep an investigation.** Export JSON, CSV, text, or an HTML report. Review it locally
  before sharing: reports can contain sensitive system and network details.
- **No AI subscription required.** Local heuristic reports work without a key. Remote AI
  is an optional, user-initiated action—not a substitute for evidence.
- **Native and portable.** Windows: C++17 + Win32. Android companion: Kotlin + Compose.
  English first; eight interface languages selectable in Settings.

## Two platforms, different capabilities

| Capability | Windows | Android companion |
|---|---|---|
| Live socket → process mapping | Windows socket tables | **Not available** without VPN capture/root; neither is implemented |
| Device-wide byte counters | NIC counters | `TrafficStats` where supported |
| Per-process/app live traffic | TCP EStats where available; subject to privilege/protocol limits | Calling UID only on modern Android; other apps show unavailable |
| Process/app identity | Paths, publisher, Authenticode, process context | Package metadata and APK signing certificate—not a malware verdict |
| Destination investigation | Observed public destinations | Addresses/hostnames you enter explicitly |
| Geo / RDAP / reputation / TLS / banners | Provider- and protocol-dependent | Provider- and protocol-dependent |
| Kill / suspend / Windows Firewall actions | Explicit actions; privileges may be required | Not implemented |
| Demo mode | `Ctrl+D`, explicitly synthetic | No demo dataset |

[Android details and restrictions](android/README-android.md)

## Try it in three minutes

### Windows

1. Build from source below, or obtain a development artifact from a successful
   [Build run](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml).
   GitHub may require sign-in to download artifacts.
2. Keep `NetLurker.exe` beside the bundled `lang/` directory. Start it normally; some
   process details and TCP statistics require administrator access. Elevated operation is
   not required just to try the UI.
3. Open Settings (`Ctrl+S`) and review external sources. **IP enrichment is enabled by
   default and sends queried addresses to providers.** Read [Privacy](PRIVACY.md) first
   if the network is sensitive.
4. Use `Ctrl+D` for labeled synthetic demo data, or find a process with `Ctrl+F`.
   Press `Enter` for an investigation report, then inspect the supporting fields.
5. `Ctrl+E` exports your findings. Redact before posting an issue.

Demo data tests the experience, not the live accuracy of a provider. A screenshot of the
demo must be labeled **DEMO / synthetic data**.

### Android

Build/install the debug APK using the commands below. Device totals, network configuration,
and manually entered destination investigations work within Android's permissions.
**Do not expect a live traffic table for every installed app.** An unsigned release APK
is not installable as a normal release; a debug APK is for evaluation, not production.

## What the scores mean

A 0–100 score is a **heuristic priority signal, not a probability of malware**. A low score
is not proof of safety, and a high score is not permission to terminate a process.

- Cloud hosting, VPNs, and upload-heavy traffic can be legitimate.
- DNSBL listing codes must be distinguished from resolver/rate-limit errors.
- Failed, disabled, or unmeasured data must not be treated as a clean result.
- TLS inspection does not establish full certificate-chain trust or revocation status.
- Server banners can be spoofed; version-family matches are not a vulnerability scan.
- AI output can be wrong or influenced by remote text. Verify it before acting.

Read the [source-by-source accuracy contract](docs/DATA-ACCURACY.md) before relying on a result.

## Build & test

### Windows x64

Install Visual Studio 2022 **Desktop development with C++** and a Windows SDK. In an
**x64 Native Tools Command Prompt** at the repository root:

```bat
python tools\gen_lang.py --check
build.bat
build\NetLurker.exe
```

Alternative build paths: `build_mingw.bat`, or CMake on Windows. `tools/build_zig.sh` can
cross-compile; cross-compilation does not replace testing on Windows.

### Android

Requirements: JDK 17, Android SDK 35, and an internet connection for Gradle dependencies.

```sh
cd android
./gradlew testDebugUnitTest lintDebug assembleDebug
# app/build/outputs/apk/debug/app-debug.apk
# With a connected emulator/device:
./gradlew connectedDebugAndroidTest
```

### Fast regression checks

```sh
python3 tools/gen_lang.py --check
python3 android/tools/gen_strings.py --check
python3 android/tools/check_symbols.py
python3 -m unittest discover -s tests -p 'test_*.py'
```

[UI regression matrix](docs/UI-REGRESSION-CHECKS.md) · [Contributing](CONTRIBUTING.md)

## Release, trust, and screenshots

Release preparation builds fresh artifacts, validates bundled languages, records the source
revision, and computes SHA-256 checksums. Hashes detect corruption; **they do not replace
code signing or a security audit**. The candidate workflow creates an artifact for review,
not an automatic public release. See the [release checklist](docs/RELEASE-CHECKLIST.md).

Windows SmartScreen may warn about an unsigned or unfamiliar binary. Do not disable your
security software to run it. Check the origin and hash, build it yourself, or wait for a
signed release.

There is not yet a verified screenshot of this revision in the README. The legacy artwork
in `docs/preview.png` and `docs/landing/` is **not evidence of current output or measured
traffic**. Replace it with a redacted capture from the tested release candidate, not an
AI-generated dashboard. [Visual provenance](docs/VISUAL-PROVENANCE.md)

## Help shape the first release

The most useful contributions right now are:

- Reproducible bugs with Windows DPI / Android version and a redacted screenshot.
- False-positive reports with the exact rule and provider status—no private API keys.
- Translation corrections and real-device tests.
- A short, honest walkthrough using a build you actually ran.

If NetLurker helps your investigation, a star helps others discover it. A bug report that
makes a result more trustworthy is just as valuable.

[Report a bug](https://github.com/thesyntax1/NetLurker/issues/new/choose) · [Security policy](SECURITY.md) · [MIT license](LICENSE)
