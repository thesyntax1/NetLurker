# NetLurker Android companion

Kotlin + Jetpack Compose · Android 8+ build target · eight languages · English first

**Experimental companion, not feature parity with Windows.** This build does not implement
VPN capture, root collection, per-app sockets, or firewall controls.

## What you can actually use

- **Investigate:** enter an IP, hostname, `host:port`, or `[IPv6]:port`; review resolution,
  available geo/reputation/RDAP answers, a TLS probe, an HTTP banner, and heuristic reasons.
- **Network:** interfaces, active link, DNS, routes and available Wi-Fi/cellular metadata.
  Permissions and device restrictions may hide fields.
- **Apps:** package names, versions, installer and APK signing metadata. Live byte counters
  are available for the calling UID on modern Android; **other applications normally have
  unavailable traffic counters**. The app does not request Usage Access or implement a
  NetworkStatsManager history collector.
- **History / Summary:** observations made during the session, device rates, and signals for
  counters that were actually available. No invented app ↔ destination graph.
- **Reports:** JSON, CSV, TXT, HTML; optional remote AI or local heuristic analysis.

Android's restriction is documented by the platform: [1](https://developer.android.com/reference/android/net/TrafficStats).
An unavailable value is shown as —/unavailable, not a measured zero. JSON includes per-app
support flags and null measurements; CSV leaves unavailable traffic fields blank.

## First run and privacy

The application starts in English regardless of the device language. Change it at the top
of Settings; the selection applies immediately and is remembered. Exports, notifications,
and the AI request language follow that selection.

Review [Privacy](../PRIVACY.md): enrichment sends entered destinations to third-party
providers. Public-IP lookup is off by default. TLS and banner probes contact the target.
The plaintext banner probe sends only an unauthenticated HEAD request, with no redirects
and a bounded response. It does not relax the general API client's cleartext policy.

Keys are stored in app-private preferences, **not encrypted by NetLurker**. No developer
telemetry, analytics, or account service is implemented. There is no synthetic demo mode.

## Build and test

JDK 17 and Android SDK 35 are required. From the repository root:

```sh
python3 android/tools/gen_strings.py --check
python3 android/tools/check_symbols.py
cd android
./gradlew testDebugUnitTest lintDebug assembleDebug
./gradlew connectedDebugAndroidTest  # connected device/emulator required
```

Install `app/build/outputs/apk/debug/app-debug.apk` for evaluation. It has a debug application
ID suffix and debug signing certificate. `assembleRelease` produces an **unsigned APK**
unless a release keystore is configured. Do not present that file as an installable public
release or promise byte-for-byte reproducibility without independently verifying it.

## Release signing

For a local signed candidate, create the ignored `android/keystore.properties`:

```properties
storeFile=/absolute/path/to/release.jks
storePassword=<local secret>
keyAlias=<key alias>
keyPassword=<local secret>
```

Never commit the file or the keystore. Keep a secure offline backup of the release key;
updates must use the same signing identity. Verify with Android SDK `apksigner verify
--verbose --print-certs`, record the certificate fingerprint, and test upgrade installation
before distribution. This repository does not currently automate Android production signing.

## CI and evidence

[Build](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml) compiles Windows and Android, runs unit tests and lint,
and uploads development artifacts. The emulator job is opt-in on ordinary builds. The
release-candidate workflow requires it and **does not publish a release**.

- `NetLurker-debug-apk`: debug-signed evaluation build.
- `NetLurker-release-apk`: minified artifact, unsigned unless configured.
- `android-smoke-evidence`: screenshot/logs from an actual emulator run, when executed.

A green build is not live-provider validation. The [accuracy contract](../docs/DATA-ACCURACY.md),
[UI matrix](../docs/UI-REGRESSION-CHECKS.md), and [release checklist](../docs/RELEASE-CHECKLIST.md)
record the remaining real-device and service checks.
