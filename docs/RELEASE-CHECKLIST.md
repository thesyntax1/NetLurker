# Release checklist

**Channel: candidate. Publication is manual.** A successful build, an installable debug APK,
and a signed public release are three different things.

## Automated candidate path

Run **Release candidate** from Actions on the revision intended for release. It reuses the
Build workflow, requires Android emulator tests, downloads the Windows artifact from that
run, verifies its recorded revision and bundled languages, and creates a ZIP plus hashes.
It has no write permission to create a release or tag. Review artifacts before publishing.

The ordinary Build workflow keeps emulator testing opt-in to avoid charging runner minutes
on every edit. The release-candidate workflow intentionally requires that more expensive job.

For local Windows packaging, use `tools/make_release.ps1` from a clean committed checkout
and an x64 developer prompt. It always rebuilds and refuses to reuse an old executable.
`tools/package_release.py` packages only a revision-marked input; it does not claim a code
signature. Production Android signing is a separate step documented in the Android README.

## Gate record for the exact candidate

Copy this table into release notes or an attached test report; do not mark skipped tests passed.

| Gate | Required evidence | Status before public launch |
|---|---|---|
| Source revision | Full SHA, candidate version, clean checkout | Record per candidate |
| Catalogs / portable tests | Successful run URL | Run against candidate |
| Windows build | Fresh MSVC x64 build and packaged revision marker | Run against candidate |
| Android unit tests / lint | JUnit totals and lint output | Run against candidate |
| Android UI | Instrumented tests + inspected emulator capture | Required, not skipped |
| Real Windows UI | Windows 10/11, normal/elevated, 100–200% DPI, EN/TR + long labels | Pending manual review |
| Real Android | At least one physical device, denied permissions, app counters unavailable, rotation/large font | Pending manual review |
| Live data | Compare socket ownership with OS tools; check device counter deltas and at least one controlled TLS/HTTP target | Pending manual review |
| Provider failure | No API key, DNS refusal, timeout, bad response, disabled source | Verify no clean/safe assertion |
| Privacy | Defaults and every outbound provider match PRIVACY.md | Review before launch |
| Artifact integrity | Verify outer ZIP checksum and every inner payload checksum | Required |
| Windows signature | Authenticode verification or explicit UNSIGNED disclosure | Required review |
| Android signature | `apksigner verify`, release fingerprint, install/upgrade test | **Block Android public APK until complete** |
| Security | Enable private vulnerability reporting, review key storage / plugin trust / untrusted inputs | Maintainer action |
| Visuals | Actual redacted candidate captures with commit/OS metadata | Old artwork is not evidence |

## Small first release, not a misleading all-platform promise

- Prefer a Windows **pre-release** with clear limitations and a 3-minute demo walkthrough.
- Label Android as experimental. Do not imply rootless live monitoring of all other apps.
- Do not claim independent malware-detection accuracy, fully verified TLS trust, current EOL
  coverage, guaranteed endpoint access, Windows 7 compatibility, or reproducible binaries
  unless the release has specific evidence for those claims.
- Ship `LICENSE`, privacy/security information, eight language files, source SHA, and hashes.
- Do not attach a raw unsigned Android release APK as though it were installable.
- Do not distribute old binaries from `build/` or `dist/` in Git. Those directories are ignored.

## After launch

1. Verify download links and hashes from a fresh machine.
2. Keep the signing identity stable for updates.
3. Triage false positives before adding more risk rules.
4. Keep a changelog that distinguishes fixes, known limitations and measured capabilities.
5. Measure activation: can a new user complete the first investigation without assistance?
   Stars are useful discovery signals, not proof of accuracy or retention.
