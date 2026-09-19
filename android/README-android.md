# NetLurker Android companion

Kotlin + Jetpack Compose · Android 8+ build target · eight languages · English first

**Experimental companion, not feature parity with Windows.** This build does not implement
VPN capture, root collection, per-app sockets, or firewall controls.

## Features

- **Investigate:** enter an IP, hostname, `host:port`, or `[IPv6]:port`; review resolution,
  available geo/reputation/RDAP answers, a TLS probe, an HTTP banner, and heuristic reasons.
- **Network:** interfaces, active link, DNS, routes and available Wi-Fi/cellular metadata.
  Permissions and device restrictions may hide fields.
- **Apps:** package names, versions, installer and APK signing metadata. Live byte counters
  are available for the calling UID on modern Android; **other applications normally have
  unavailable traffic counters**. The app does not request Usage Access or implement a
  NetworkStatsManager history collector.
- **History / Summary:** observations made during the session, device rates, and signals for
  counters that were actually available. No per-app destination graph is available.
- **Reports:** JSON, CSV, TXT, HTML; optional remote AI or local heuristic analysis.

Android's restriction is documented by the platform: [1](https://developer.android.com/reference/android/net/TrafficStats).
An unavailable value is shown as —/unavailable, not a measured zero. JSON includes per-app
support flags and null measurements; CSV leaves unavailable traffic fields blank.

## First run and privacy

The application starts in English regardless of the device language. Change it at the top
of Settings; the dialog previews your choice, and **Save** applies and remembers it.
**Cancel** or Back discards the draft. Save/Cancel stay below the scrollable form,
including on compact screens. Cache and OS-permission actions are separate, immediate actions. Exports, notifications,
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
unless a release keystore is configured. An unsigned release APK is not installable
as a normal release. Reproducible builds have not been verified.

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
before distribution. Public release automation supports these checks with repository
signing secrets; see the setup section below. Ordinary CI exercises the signing path
with a disposable fixture key, never with your production key, and never uploads that fixture APK.

## CI and evidence

[Build](https://github.com/thesyntax1/NetLurker/actions/workflows/build.yml) compiles Windows and Android, runs unit tests and lint,
and uploads development artifacts. The emulator job is opt-in on ordinary builds. The
Release workflow can require it via `RELEASE_RUN_EMULATOR=true`; otherwise it is
explicitly not executed. Manual Release preparation defaults to no publication.
Publishing a GitHub Release triggers asset delivery; see the [operator guide](../docs/RELEASES.md).

- `NetLurker-debug-apk`: debug-signed evaluation build.
- `NetLurker-release-apk`: minified artifact, unsigned unless configured.
- `android-smoke-evidence`: screenshot/logs from an actual emulator run, when executed.

A green build is not live-provider validation. The [accuracy contract](../docs/DATA-ACCURACY.md),
[UI matrix](../docs/UI-REGRESSION-CHECKS.md), and [release checklist](../docs/RELEASE-CHECKLIST.md)
record the remaining real-device and service checks.


### Automated public APKs

The shared root `version.json` controls Android versionName/versionCode. Release CI
stamps it from the tag before compilation; see the documented bounded version policy.
The unsigned minified CI artifact is then zipaligned, signed using repository secrets,
and checked with `apksigner`, `zipalign` and `aapt2`. The application ID must be
`dev.netlurker.android`, never `.debug`, and the certificate must match the separate
`ANDROID_SIGNING_CERT_SHA256` repository variable.

Configure `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`
and `ANDROID_KEY_PASSWORD` under GitHub Actions repository secrets. Keep the same
production key and an offline backup. No signing secrets are supplied to ordinary PR
builds. Android publication is off by default; unused or unfinished Android settings do
not block a Windows-only release. Set `REQUIRE_ANDROID_RELEASE=true` to explicitly
enable Android publication and require complete, verified signing. Once enabled,
partial configuration or failed verification always fails. No signing setup is needed
to try a development debug APK; it is not a production release.
See [release setup and recovery](../docs/RELEASES.md). A signed APK still needs a
physical-device install/upgrade test before claiming public-release readiness.
