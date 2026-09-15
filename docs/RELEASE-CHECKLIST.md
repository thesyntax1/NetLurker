# Release checklist

**Publication is maintainer-triggered, file delivery is automatic.** A green CI run,
a debug APK and a reviewed public release are not the same thing. Pressing **Publish
release** is the maintainer's decision that the manual gates below are ready.

## Automated release path

The **Release** workflow runs on `release.published`, resolves the tag's exact commit,
stamps a shared Windows/Android version, reuses Build tests, packages a Windows ZIP
and installer, and uploads verified assets to that existing release. It produces a
manifest and SHA-256 list, preserves human release notes, and refuses different bytes
under an existing asset name. Only the upload job has `contents: write`.

A manual dispatch defaults to **preparation only** (`publish=false`), using the selected
branch; it creates review artifacts without creating/publishing a tag or release.
See [the release operator guide](RELEASES.md) for setup, signing, retries and version rules.

Android public APKs require a production keystore and pinned certificate fingerprint.
Without any Android signing secrets, Android is explicitly omitted, never replaced with
a debug/unsigned APK. Set `REQUIRE_ANDROID_RELEASE=true` to make omission a hard failure.
Windows signing is optional with explicit UNSIGNED disclosure; set
`REQUIRE_WINDOWS_SIGNATURE=true` to require it. Partial signing configuration is an error.

Emulator execution remains opt-in (dispatch input or `RELEASE_RUN_EMULATOR=true` repository
variable) because it uses additional runner time. UI-test compilation is always run;
skipped emulator execution is **not** UI verification. Complete the device matrix before
claiming a reviewed general release. No workflow automatically completes the manual gates.

Local Windows packaging uses `tools/make_release.ps1` from a clean committed checkout
and x64 developer prompt. It validates the shared version and always rebuilds; it never
silently packages a stale executable or publishes it.

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
