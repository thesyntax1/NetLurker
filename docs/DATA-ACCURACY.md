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
   Aggregate Windows threat disk-cache reuse has now been removed as well; it could not preserve provider failures and configuration changes.
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


## Second audit: provider identity, continuity and synthetic provenance

Implemented corrections (the exact revision's CI remains the source of test results):

- **AbuseIPDB omissions:** Windows no longer infers score 0 for an address absent from a
  block response. It queries each requested IP; both platforms validate the response IP,
  required score/report fields, integer types and bounds. This may use more individual
  requests than batching; no shared key or quota-bypass mechanism is supplied.
- **VirusTotal:** wrong-address/type, missing/negative/fractional/overflowed counts and
  zero usable engines are unavailable, not clean. The denominator is the sum of actual
  verdict categories (malicious/suspicious/harmless/undetected), excluding timeout/failure.
- **Passive DNS:** validate array or newline-delimited records and their queried address.
  An empty valid array is a measured zero; an HTTP/error object or invalid record is not.
- **Windows JSON boundary:** the above parsers reject incomplete/trailing documents,
  duplicate keys, excessive nesting and non-finite/malformed numbers. This is a targeted
  provider parser, not a claim that every legacy JSON consumer has been replaced.
- **Ownership dates:** Windows handles ISO offsets/calendar validity; Android cannot use a
  future registration date as proof of a young or established network. RDAP error/empty
  objects are rejected and technical contacts are no longer called abuse contacts on Android.
- **Android target identity:** DNS resolution cannot change the target key. Separate
  hostnames on the same port no longer collide as `null:443`; incarnation checks prevent
  removed/re-added targets accepting old results. Removal/configuration changes cancel jobs.
- **Source switches:** Windows schedules DNSBL/Abuse/CIRCL independently of RDAP/VT and
  rejects results from old configurations. Android RDAP/VT no longer depend on the general
  threat toggle. Already transmitted requests cannot be recalled.
- **Cache honesty:** Android rejects future/expired entries and incomplete/type-invalid
  payloads; malformed RDAP cache data falls through to a real query. Windows aggregate
  threat cache files are discarded rather than reclassified as current evidence.
- **Traffic attribution:** shared Android UIDs are not attributed to individual packages;
  those package counters remain unavailable. History uses package identifiers rather than
  potentially duplicate/localized labels, reseeds after gaps, and synchronizes snapshots.
- **Empty AI shortlist:** Windows no longer calls the system clean just because the current snapshot has no connection scoring at least 25.
- **Plugin provenance:** Windows plugin output is kept separate and exported separately;
  it is no longer substituted for an AbuseIPDB score or fed into AbuseIPDB scoring rules.
- **Demo provenance:** Windows demo rows cannot drive termination, suspension, firewall,
  properties, remote re-query/browser actions or AI actions. They do not update live anomaly/rate baselines or fetch real
  metadata for a coincidentally matching PID. CSV now has a `data_source` column; JSON,
  text and HTML retain their demo markings. Live-only history/statistics/graph tabs require
  leaving demo mode. Source-guard tests are structural; no destructive actions run in CI.
- **Spreadsheet text:** CSV application/provider text is protected against formula interpretation, and embedded separators/quotes are escaped.
- **Exports:** missing threat/VT/PDNS measurements use null/blank rather than fabricated
  zeroes; Android includes per-result timestamps/details and Windows a threat status.

New regression suites: `provider_evidence_test.cpp`, expanded `evidence_rules_test.cpp`
(32 source-switch combinations), `ProviderEvidenceTest.kt` and `test_provenance_guards.py`.

Still not established: live provider access/coverage, exhaustive special-use address
classification, runtime race stress across every platform lifecycle, full TLS trust, or
an end-to-end detection accuracy percentage. Strict validation may reject an equivalent
IPv6 textual representation on Windows; this fails unavailable, never as a clean result.
