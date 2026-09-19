# NetLurker

[![Build](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml/badge.svg)](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Türkçe](README.tr.md) · [Downloads](https://github.com/thesyntax1/NetLurker/releases) · [Build & test](#build--test) · [Contact](#contact)

NetLurker is a Windows network monitor written in C++17 and Win32. It lists TCP/UDP
connections with their owning processes and lets you inspect destinations, process
metadata and risk indicators. The Android companion is written in Kotlin and Compose;
it supports device network information and investigations of addresses you enter.

The project is still in development. Published packages belong in
[Releases](https://github.com/thesyntax1/NetLurker/releases); Actions artifacts are
unreviewed development builds.

## Features

- Process-to-connection mapping, filtering and sorting on Windows.
- IP geolocation, RDAP, DNSBL, AbuseIPDB, VirusTotal, TLS and HTTP banner lookups,
  subject to provider access and configuration.
- Rule-based risk scores with reasons, plus optional analysis through an
  OpenAI-compatible endpoint. Local reports work without an AI key.
- JSON, CSV, HTML and text exports.
- English, Türkçe, Español, Deutsch, Français, 日本語, 中文 and Português.
- A portable Windows build and a labeled demo dataset for trying the interface.

## Download

| Platform | File |
|---|---|
| Windows installer | `NetLurker-v…-setup.exe` under a release's Assets |
| Windows portable | `NetLurker-v…-win64.zip`; extract the whole archive, including `lang/` |
| Android development build | `NetLurker-debug-apk` from a successful [Build run](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml) |

If no release is available, use a successful Build run or compile from source below.
GitHub may require sign-in to download Actions artifacts. The automatic “Source code”
archives are not compiled applications.

Compare release downloads with `SHA256SUMS.txt`. Windows packages may be unsigned;
check the release's signature information and don't disable security protection to run
a download. Android production publication is off by default. Debug APKs are for testing;
an unsigned release APK is not a substitute for a signed, installable release.

## Getting started

1. Start `NetLurker.exe`. For the portable build, keep `lang/` beside the executable.
   Some process details and TCP statistics require administrator access, but opening
   the interface does not.
2. Open Settings with `Ctrl+S`. **IP enrichment is enabled by default and sends queried
   addresses to providers.** See [Privacy](PRIVACY.md) before using it on a sensitive network.
3. The first launch is in English. The language picker is at the top of Settings;
   choose a language and Save. Cancel leaves the saved setting unchanged.
4. Use `Ctrl+F` to find a process, then select a connection to inspect it. In live mode,
   `Enter` opens analysis; `Ctrl+E` exports the current findings. Review reports for
   private addresses, paths and keys before sharing them.
5. `Ctrl+D` toggles synthetic demo data. AI, process-control and remote-query actions
   are disabled in demo mode. `F1` lists the keyboard shortcuts.

If the table is empty, clear the search filter and check while an application is
connecting. An unavailable field means a measurement or lookup could not be obtained;
it is not a measured zero or a clean result.

## Platform limits

Windows reads OS socket tables. Snapshots can miss short-lived connections, and
per-process traffic measurements depend on TCP EStats support and privileges.

Android does **not** implement VPN capture, root collection, per-app socket attribution
or firewall controls. On modern Android, other apps' live UID counters are generally
unavailable. Device totals and manually entered destination lookups are separate from
per-app measurements. See the [Android guide](android/README-android.md).

The 0–100 score is a rule-based investigation priority, not a probability of malware.
Provider errors, missing data and legitimate VPN/cloud traffic can affect what you see.
TLS inspection does not establish full chain or revocation trust; server banners can
be spoofed, and AI output needs checking. The [data reference](docs/DATA-ACCURACY.md)
describes the sources, validation rules and remaining limits.

## Build & test

### Windows x64

Install Visual Studio's **Desktop development with C++** tools and a Windows SDK.
Run these commands from an **x64 Native Tools Command Prompt** at the repository root:

```bat
python tools\gen_lang.py --check
build.bat
build\NetLurker.exe
```

Other build paths are `build_mingw.bat`, CMake on Windows and `tools/build_zig.sh` for
cross-compilation. A cross-compiled binary still needs runtime testing on Windows.

### Android

Requirements: JDK 17, Android SDK 35 and network access for Gradle dependencies.

```sh
cd android
./gradlew testDebugUnitTest lintDebug assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
./gradlew connectedDebugAndroidTest  # requires a device or emulator
```

### Repository checks

```sh
python3 tools/gen_lang.py --check
python3 android/tools/gen_strings.py --check
python3 android/tools/check_symbols.py
python3 -m unittest discover -s tests -p 'test_*.py'
```

Release automation prepares Windows ZIP/installer packages by default. Android
publication requires an explicit opt-in and verified production signing. Maintainer
instructions are in [Releases](docs/RELEASES.md) and the
[release checklist](docs/RELEASE-CHECKLIST.md). CI does not replace device testing.

## Contributing

Bug reports, translation fixes and small pull requests are welcome. Include your build
version, OS and reproduction steps in an [issue](https://github.com/thesyntax1/NetLurker/issues/new/choose).
For UI changes, attach a redacted screenshot of the running build; keep the DEMO label
visible for synthetic data. Older artwork is not a current screenshot—see the
[visual asset notes](docs/VISUAL-PROVENANCE.md).

[Contribution guide](CONTRIBUTING.md) · [UI checks](docs/UI-REGRESSION-CHECKS.md) · [Roadmap](docs/ROADMAP.md)

## Contact

Developer contact:

- TikTok: [szoboszlai2113](https://tiktok.com/szoboszlai2113)
- Email: [user2102392109@proton.me](mailto:user2102392109@proton.me)

Use GitHub issues for bugs and feature requests so the discussion is easy to follow.
For security reports, use the private channels in [SECURITY.md](SECURITY.md), not a
public issue or social-media comment.

## License

[MIT](LICENSE).
