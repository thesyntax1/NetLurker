# Visual provenance

The following legacy assets were present before release hardening:

- `docs/preview.png`
- `docs/landing/preview.png`
- `docs/landing/hero.png`

They are **not verified captures of the current application revision**. The preview images
contain data/layout inconsistencies and do not establish live measurements. The hero is
concept artwork. Previous text calling the preview a real running screenshot has been
removed. Preserve these files as legacy artwork only, not as test or accuracy evidence.

## Capturing publishable evidence

1. Build the exact candidate revision and record OS version, DPI/font scale, language and commit.
2. Capture the running application, without compositing invented findings into it.
3. Prefer the explicit Windows demo for a public walkthrough; keep the DEMO marker visible.
4. For live data, redact private addresses, account names, paths, command lines and keys.
   State that the capture is redacted; do not change values to look more impressive.
5. Show one normal workflow and one missing-provider/permission state. Do not cherry-pick a
   success screen to imply all sources or platforms always work.
6. Store a short capture note next to the asset. Android emulator screenshots can come from
   the `android-smoke-evidence` artifact, but must be inspected and redacted before committing.

No new synthetic dashboard should be labeled as a screenshot.
