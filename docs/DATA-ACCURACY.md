# Data accuracy: measurements, inference, and unknowns

NetLurker is an investigation aid, not an antivirus or an independent reputation authority.
No end-to-end accuracy percentage has been established. The score is a hand-weighted
heuristic; the Windows and Android sampling units are different and scores are not calibrated
against each other.

## Evidence map

| Evidence | What is actually observed | Important limitation |
|---|---|---|
| Windows connections | Windows TCP/UDP owner tables | Snapshots can miss short-lived connections; UDP has no TCP-style remote connection state |
| Windows rates | NIC counters and available TCP EStats | Device totals are not a sum of complete per-process measurements; access/protocol limits apply |
| Android device rates | `TrafficStats` counter deltas / monotonic elapsed time | Device totals, not destination attribution |
| Android app rates | Calling UID counters where available | Android 7+ restricts other UID counters; unsupported values must remain unknown, including in exports |
| Process / package identity | OS metadata, signing certificate information | A signature establishes identity/integrity properties, not benign intent; multiple Android packages can share a UID |
| Geo / ownership | Provider answers | Approximate, possibly stale; HTTP geolocation has no transport authenticity |
| DNSBL | Explicit supported listing response codes | Resolver refusals, timeouts and ambiguous DNS failures are not a listing or proof of cleanliness |
| AbuseIPDB / VirusTotal | Provider scores and submitted reports | Provider coverage, access limits, freshness and false reports affect the result |
| TLS | Certificate presented to a probe | Not full chain/revocation validation; user-entered hostname is used for Android SNI, not an inferred PTR identity |
| HTTP banner | Server-provided response headers | Can be spoofed or absent; version-family hints are not exhaustive EOL/CVE validation |
| Anomaly / heartbeat | Changes/regularity in observed samples | Backups, updates, streaming and polling can legitimately trigger signals |
| AI | Model interpretation of collected context | Not new measurement; verify every claim, especially instructions in remote text |

## Corrections made during release hardening

1. **Android sample timing:** device sampling no longer overwrites the per-UID timestamp
   before app rates are calculated. Unsupported → supported transitions and counter resets
   do not turn since-boot totals into traffic spikes.
2. **Unavailable app counters:** UI uses unavailable/—, JSON uses `null` plus a support flag,
   and CSV leaves unavailable measurements blank instead of exporting invented zeroes.
3. **DNSBL false positives:** resolver/rate-limit return codes and non-listing addresses
   cannot add blacklist risk. `InetAddress`/`getaddrinfo` do not expose an authoritative RCODE,
   so ambiguous failures are marked incomplete, not clean. The legacy SORBS zone is no longer queried.
4. **Windows version matching:** `nginx/1.2` no longer matches `nginx/1.25.3`. Bare product
   family strings such as `jboss` are not enough to assert end of life.
5. **Windows evidence merging:** AbuseIPDB results update their own fields instead of
   erasing concurrent DNSBL/RDAP/VirusTotal results. Worker flags remain active until IO ends.
   A new cache namespace avoids reusing old false-positive blacklist results.
6. **Android threat cache:** unsafe aggregate reuse is removed. Partial results and disabled
   providers remain visible; RDAP keeps its independent success cache.
7. **Android TLS / dates / input:** use the entered hostname for SNI and name checks, separate
   certificate cache keys by host, recompute date flags for cached certificates, respect ISO
   timezone offsets, and do not parse an IPv6 hextet as a port.
8. **Inference wording:** incomplete/failed sources remain incomplete; an absent reverse DNS
   response does not establish maliciousness. Android's lowest badge reads LOW SIGNAL rather
   than promising SAFE.

## Validation boundaries

Unit tests pin arithmetic and parsing, not third-party truth. Cross-compilation proves a
binary can link, not that it renders on a particular machine. An emulator is not evidence
that OEM traffic permissions behave identically. See [release gates](RELEASE-CHECKLIST.md)
for tests that must be run against the exact candidate revision.

Known limits to retain in a release announcement:

- No Android VPN capture, root collector, per-app destination mapping, or firewall.
- No complete malware verdict, guaranteed threat feed coverage, or fully verified TLS trust.
- CIRCL, DNSBLs and other external services may refuse requests; missing data is not success.
- Broad Windows 7 support has not been revalidated; test your supported Windows versions
  before promising compatibility.
- API keys currently rely on OS file/app isolation, not application-level encryption.
- Live provider checks and real-device visual review still need a release evidence record.

## References

- Android UID counter restriction: [1](https://developer.android.com/reference/android/net/TrafficStats).
- Spamhaus resolver/rate-limit codes are not reputation data: [2](https://www.spamhaus.org/resource-hub/dnsbl/using-our-public-mirrors-check-your-return-codes-now/).

Do not use the old promotional artwork as proof that any of these observations were made.
