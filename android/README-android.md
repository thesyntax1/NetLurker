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
./gradlew lintDebug
```

Release signing is optional: drop a `keystore.properties` next to `settings.gradle.kts` and
the release APK is signed with it; otherwise it is left unsigned and the workflow says so
instead of implying it is distributable.

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
