# Privacy and external requests

NetLurker does not include an analytics, advertising, or developer telemetry service.
**That does not mean it makes no external requests.** Enrichment and active probes are
network operations; the providers and targets can log them.

## What can leave the device

| Feature | Destination / transmitted data | Trigger |
|---|---|---|
| Geolocation | `ip-api.com`: queried IP, your request's source IP | Enabled by default; Windows observed public destinations, Android entered targets |
| DNSBL | System DNS resolver and configured DNSBL zones: reversed queried IPv4 | Threat lookups enabled by default |
| Reverse DNS | System resolver: queried IP | Destination investigation/enrichment |
| RDAP | `rdap.org`, then the registry it redirects to: queried IP | Enabled by default |
| Passive DNS | Configured CIRCL endpoint: queried IP | Threat lookups; endpoint access may fail or require service-specific access |
| AbuseIPDB | `api.abuseipdb.com`: queried IP/network and personal API key | Key configured and lookup enabled |
| VirusTotal | `virustotal.com`: queried IP and personal API key | Configured/enabled; browser links are separate actions |
| TLS / HTTP banner probe | Target host/port: connection, TLS ClientHello or unauthenticated HTTP HEAD | Windows enrichment / Android entered investigation; respective switch enabled |
| Remote AI | User-configured endpoint: investigation context and API key | Explicit AI action; local fallback makes no AI request |
| Public IP check (Android) | `api.ipify.org` / `api64.ipify.org`: request source IP | Off by default; user enables it |
| Browser actions | Chosen website: IP, domain or hash in the URL | User clicks an external link |

The free geolocation endpoint uses **HTTP, not authenticated HTTPS**. Its response can be
observed or modified in transit. Do not treat geolocation-derived heuristics as strong
security evidence. Plaintext banner probes are intentionally limited to unauthenticated
requests to the investigated target; they are not an authenticated browsing session.

Remote AI context can include IPs, hostnames, process paths, command lines, user names,
package names, and findings, depending on platform and investigation. Review the code and
the chosen provider's policy before enabling it. A custom endpoint is not automatically safe.

## Local storage

- Windows configuration, keys, caches and history are stored under `%APPDATA%\NetLurker`.
- Android settings and keys use app-private SharedPreferences; caches use app-private files.
  Android backup is disabled in the manifest.
- **API keys are not encrypted by this application.** OS user/app isolation is the current
  protection. Do not share the configuration directory, APK signing keystore, or full logs.
- Exports are written only after a user action, but can contain sensitive system/network
  data. Android uses the Storage Access Framework so the user selects the destination.
- Clearing enrichment caches does not erase all settings, keys, baselines, or exported files.
  Remove those separately if you need to wipe the installation.

## Safer use

Review Settings before monitoring a sensitive network; disable unwanted external sources.
The current Windows defaults may start enrichment before you open Settings, so use an
isolated test environment for first-run evaluation when policy prohibits external lookups.
Do not upload raw exports as public bug reports. Redact IPs, names, paths, commands, and keys.
Probe only systems you own or are permitted to investigate.
