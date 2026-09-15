# NetLurker for Android

The Android build of NetLurker: same dark interface, same risk model, same eight
languages, same rule — **honest data, or none at all**.

It is a native Kotlin + Jetpack Compose app in [`android/`](android/), built by
[`.github/workflows/android.yml`](../.github/workflows/android.yml) into a debug and a
release APK on every push.

---

## The one thing Android will not give you

On Windows, NetLurker reads the kernel socket tables (`GetExtendedTcpTable`) and maps every
socket to a process, its signature and its publisher.

**An unrooted Android app cannot do that.** Since Android 10, SELinux denies untrusted apps
`/proc/net/tcp`, and the framework exposes no per-application socket list. So this build
ships **no connection table** and never draws an application ↔ destination edge it did not
measure. Where the desktop build shows a row per socket, this build shows what the platform
genuinely reports and says plainly what it cannot answer.

Everything else — geolocation, DNS blacklists, AbuseIPDB, CIRCL passive DNS, RDAP
ownership, VirusTotal, TLS inspection, HTTP banners, the risk engine, the EMA + 3σ anomaly
detector, the four export formats — is ported and works the same way.

If you want the socket table on Android, it needs a local VPN capture (PCAPdroid-style) or
root. Neither is in this build; see *Not included* below.

## What the app really reads

| Panel | Source | Notes |
|---|---|---|
| **Apps** | `TrafficStats` per-UID counters | Cumulative since boot; the rate shown is the delta over the last poll. If the counter is unsupported the row says so instead of showing `0`. |
| **Apps → detail** | `PackageManager` | UID, version, target SDK, installer of record, **APK signing certificate** (subject, issuer, SHA-256) and APK SHA-256 on demand. Android has no Authenticode; this is the real equivalent. |
| **Network** | `ConnectivityManager`, `NetworkInterface` | Transport, validated, metered, roaming, VPN, captive portal, addresses, DNS servers, search domains, routes, MTU. |
| **Wi-Fi** | `WifiManager` / `TransportInfo` | SSID, BSSID, RSSI, link speed, band, IP, gateway. The SSID needs the location permission on Android 10+; without it the field says *"hidden by Android"* rather than showing a guess. |
| **Cellular** | `TelephonyManager` | Operator and generation; the identity is unavailable without the phone permission, and the card says so. |
| **Investigate** | live lookups | You give it an address, host or `host:port`; it resolves, reverse-looks-up, geolocates, queries 5 DNSBLs, CIRCL, RDAP, optionally AbuseIPDB and VirusTotal, performs one TLS handshake and one HTTP `HEAD`, then scores the result. |
| **History** | session state | 2-minute rate window, per-application baselines, anomaly alerts. |

## The honesty contract

Same wording as the desktop README, enforced in code:

| Situation | What you see |
|---|---|
| Lookup still running | `querying…` |
| Lookup failed | `lookup failed — <the real error>` |
| No network | `offline` |
| Source switched off, or missing an API key | `turned off — <which one>` |
| Impossible on this device | `not available on this device` |
| Private address | *"no geolocation exists"* — not a failed lookup |

A failed lookup is **never** written to the disk cache, and retries use exponential backoff
(20 s → 10 min), so a dead endpoint cannot become a permanent verdict. Cached answers are
always displayed with the timestamp they were fetched at.

There is no demo mode and no sample data on Android: the desktop build's `DEMO MODE` button
deliberately did not make the crossing.

## Risk model

Ported from `EvaluateRisk()` in `src/netmon.cpp`, including the rule that SMB, RDP, MS-RPC,
NetBIOS and VNC only count when they face the internet. Rules that depended on a Windows
process (signature state, suspicious install path, suspended process, auto-start
persistence) are **absent**, because Android gives an unrooted app no way to attribute a
socket — and an invented owner would poison every judgement built on it.

A source that has not answered contributes **nothing** to the score, and the verdict says
so (`Still querying: geo, threat, cert, banner`) instead of treating an absence as a clean
result.

The anomaly detector is the desktop EMA + variance model unchanged (α = 0.15, warm-up 24
samples, outlier above `ema + 3σ` or `3 × ema`); only the unit changes — bytes per second
per application instead of new connections per minute — with the floor raised accordingly.

Three more desktop rules survived the port, because they need traffic rather than sockets.
Their thresholds are the desktop's, so a score means the same thing on both platforms; only
the unit they are applied to differs.

| Rule | Desktop | Android | Points |
| --- | --- | --- | --- |
| Hosts-file redirect | `IsHostsRedirect()`, `src/dns.cpp` | same parse of `/system/etc/hosts`, re-read at most once a minute, scored only for public addresses | +15 |
| Exfiltration ratio | `rateOut > 200 KiB/s` and `> 6 × rateIn` | identical, per application, and disabled entirely when the counters are unsupported | +20 |
| Heartbeat | `netmon.cpp:948`, ≤ 24 events, 30-minute window, ≥ 4 hits, mean 2–900 s, `sd/mean < 0.25` | same arithmetic per application, fed by the rising edge over a 2 KiB/s burst floor | +25 within 120 s, else +12 |

The hosts file is read, never guessed: when Android refuses it to an unprivileged app the
network tab says so in plain words rather than showing an empty list that would read as
"nothing is redirected".

Still absent, and absent for a reason rather than an oversight: the desktop's port-scan,
ARP, DNS-cache and listening-socket rules all need a socket table or a raw socket, and the
Windows-only process rules (signature state, suspended, persistent) have no Android
counterpart an unrooted app can reach.

## Languages

Eight, generated from one catalog by
[`android/tools/gen_strings.py`](android/tools/gen_strings.py):

```
python3 android/tools/gen_strings.py          # write res/values*/strings.xml
python3 android/tools/gen_strings.py --check  # verify; CI runs this before compiling
```

`--check` fails when a key used in Kotlin is missing from any locale, when a locale has an
empty value, when a `{placeholder}` differs between languages, or when a checked-in
`strings.xml` is stale. The bad-port rule notes are taken **verbatim** from the desktop
`lang/*.ini` files, so a rule reads identically on both platforms.

## Build

```bash
cd android
./gradlew assembleDebug          # app/build/outputs/apk/debug/app-debug.apk
./gradlew testDebugUnitTest      # risk model, baselines, formats, exports, parsers
./gradlew connectedDebugAndroidTest   # needs a device: renders all five tabs
./gradlew lintDebug
```

Release signing is optional: drop a `keystore.properties` next to `settings.gradle.kts` and
the release APK is signed with it; otherwise it is left unsigned and the workflow says so
instead of implying it is distributable.

## Continuous integration

`.github/workflows/build.yml` builds both platforms on every push and uploads the results as
run artifacts, so a build never has to happen on a developer machine:

| Artifact | Contents |
| --- | --- |
| `NetLurker-windows-x64` | `NetLurker.exe` (MSVC x64, static runtime), `lang/*.ini`, `SHA256SUMS.txt` |
| `NetLurker-debug-apk` | debug-signed APK, installable as-is |
| `NetLurker-release-apk` | minified APK, unsigned unless `keystore.properties` was present |
| `android-build-log` | the Gradle output of the Android job |
| `android-smoke-evidence` | emulator logcat, activity dump, screenshot, instrumented UI test log |

The Windows job deletes the `build/NetLurker.exe` that is checked into the repository before
compiling. Without that step a failed compile would still leave the committed binary behind
and the artifact would look like a success. Both jobs also run their string-catalog check
first, so a missing translation fails the build rather than reaching a user.

Before Gradle runs at all, `android/tools/check_symbols.py` resolves every project-internal
import and enum reference in the Kotlin sources. It is not a compiler and it does not claim
to be: it exists because "Unresolved reference" is the one failure mode that costs a full
cold CI run to discover, and it takes a second to catch locally.

A third job boots an API 34 emulator, installs the debug APK, launches the activity,
watches logcat for a crash and then runs `connectedDebugAndroidTest` against it — the
instrumented tests compose all five tabs for real. That is the only automated evidence the
app renders, since no unit test can tell you a composable survived missing data.

It is **on demand**, not on every push: booting a virtual device costs more runner minutes
than the two builds combined, and on a private repository those minutes are billed. Tick
`run-emulator` when you trigger the workflow manually and the job runs; otherwise it is
skipped and every push still produces both APKs and the Windows exe.

```
gh workflow run Build --ref <branch> -f run-emulator=true
```

The job's verdict is published as the `android-smoke-report` check run — logcat crash
markers, the resumed activity, every script step's exit code and the instrumented test
result — because run artifacts cannot be read through the API, only check runs can.

## Not included (and why)

- **Connection / socket table** — blocked without root or a VPN capture; not faked.
- **Blocking an IP** — Android offers no unrooted firewall API. The context menu opens
  VirusTotal, AbuseIPDB, CIRCL and RDAP for the address instead.
- **Process kill, DLL modules, Windows Firewall rules** — no Android equivalent.
- **Network graph edges** — see the summary tab, which states this in the UI.

## Permissions

`INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `QUERY_ALL_PACKAGES` (to name the
applications behind the traffic counters), and — only if you grant them at runtime —
`ACCESS_FINE_LOCATION` (SSID) and `POST_NOTIFICATIONS` (anomaly alerts). No storage
permission: exports go through the Storage Access Framework, to a location you pick.

No telemetry, no analytics, no account.

## One deliberate difference from the desktop

The end-of-life banner check uses the desktop's signature list but not its matching rule.
`src/banner.cpp` searches for a plain substring, so `nginx/1.2` also matches `nginx/1.25.3`
and the desktop calls a current server end of life. The Android build keeps the same list and
requires a signature ending in a digit to stop at a version boundary, so `nginx/1.2.9` and
`apache/1.3.41` still match while `nginx/1.25.3` and `PHP/8.3.1` do not. The cases are pinned
in `ProbeParsingTest`. The trade-off runs the other way for one signature: `lighttpd/1.4.2`
no longer reaches `lighttpd/1.4.25`. Missing a 2011 web server is preferable to accusing a
current one.
