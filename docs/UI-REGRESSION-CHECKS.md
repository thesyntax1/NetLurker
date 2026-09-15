# UI and language regression checks

## Expected language behavior

- With no saved preference, start in English, regardless of the OS language.
- Select a language in Settings. Labels update without restarting; the current tab remains selected.
- Close/reopen the application: retain the selected language.
- A previously saved explicit system/auto preference is still respected. An invalid preference falls back to English.
- Android exports, AI request language, and notifications use the selected application language too.

## Automated checks

```sh
python3 tools/gen_lang.py --check
python3 android/tools/gen_strings.py --check
python3 android/tools/check_symbols.py

g++ -std=c++17 -Wall -Wextra -Werror -Isrc tests/ui_layout_test.cpp -o /tmp/netlurker-layout-test
/tmp/netlurker-layout-test
```

The portable layout test covers exact-fit/wrapping boundaries, all 19 toolbar controls,
126 window/DPI/translation combinations, and 10,000 deterministic randomized cases.
It checks bounds, spacing, item preservation, and non-overlap. It does not measure real fonts.
The Windows CI job also runs it with MSVC.

With JDK 17, Android SDK 35 and a connected device/emulator:

```sh
cd android
./gradlew testDebugUnitTest lintDebug connectedDebugAndroidTest
```

`LanguageAndLayoutTest` covers English-first behavior on a Turkish resource configuration,
saved preferences, live Settings language selection, and non-overlapping detail rows at
260 dp / 200% font scale. `ScreenRenderTest` grants runtime permissions before rendering
so OS permission windows cannot obscure the UI assertions, and disposes its ViewModels.

## Manual visual checks still required

### Windows

- Resize through 900, 1024, 1366, 1920 logical-pixel widths at 100%, 125%, 150%, 200% DPI.
- Repeat in English, Turkish, German, French, Japanese, and Chinese.
- Ensure navigation stays separate from rates/badges; all filters and action buttons wrap
  without covering the search field. Try each filter, Pause/Resume, Details, and Settings.
- With Details enabled, resize vertically and check the table, detail panel, and status bar.
- Change language while paused and press Save: toolbar labels and hit regions should update immediately. Cancel must preserve the previous language.
- Inspect the multiline threat checkbox and help text above Save/Cancel in Settings.

### Android

- Check 320/360/411 dp phones, landscape, and a tablet, with 100% and 200% font sizes.
- Confirm header actions remain reachable, long filter rows scroll, and investigation
  source/action rows wrap. Open a detail containing a long IPv6 address/fingerprint.
- Open Settings with the keyboard visible; scroll to the final controls and close it.
- Change language, change tabs, rotate, export, and reopen the application.
- On Android 12+, test precise and approximate location responses. On Android 13+, test
  notification permission acceptance/denial. Denial must not block the rest of the UI.

## Validation in this change

Passed locally: both catalog checks, Kotlin internal-symbol check, portable layout tests,
and complete Windows x64 cross-compilation/linking (Zig 0.14.1, including the RC file).
The Android SDK/emulator was unavailable in the editing environment, so Android compilation,
instrumented tests, and native visual checks need the configured CI/device environment.
No generated executable or APK is included in this source change.


## Settings regression pass (Save/Cancel redesign)

Automated coverage is not a substitute for the visual/IME checks below. Consult the
specific revision's CI result before treating any newly added test as passed.

- Portable geometry: 252 settings viewport/DPI cases in `tests/ui_layout_test.cpp`.
- Windows native controls: `tests/settings_dialog_test.cpp` creates the real resource
  dialog, checks 15 DPI/height combinations, pinned actions while scrolling, nested
  tab order and masked keys. This is structural Win32 testing, not a visual review.
- Windows persistence: `tests/config_store_test.cpp` checks Unicode, preservation of
  unknown sections, failed read-only/locked replacement, and line-break injection.
- Windows transport: eight controlled loopback fixtures in `test_http_transport.py`
  exercise production WinHTTP (query strings, redirects, truncation, size boundary,
  HTTP failure, plaintext credentials and header injection). No public provider is used.
- Android JVM: draft immutability, full 1–30 s range, HTTPS/model validation, single
  preference transaction and failed-commit in-memory rollback.
- Android instrumentation: Save versus Cancel language semantics and a 320×360 dp,
  200% font settings dialog with actions stationary before/after scrolling. Compilation
  alone does **not** mean these tests ran on an emulator.

### Manual checks still required

1. Android: use portrait and landscape, 200% font, gesture and three-button navigation.
   Focus the bottom API-key field with the soft keyboard visible. Both footer actions
   must be fully reachable above the IME; no overlap or hidden error text.
2. Edit several fields and language. Cancel, Back and outside-tap must not change
   preferences. Reopen, Save, force-stop/relaunch and verify all changes persisted.
   Keys stay masked and are not copied into the activity saved-state Bundle. Rotation
   discards an unsaved draft deliberately; it must not silently apply it.
3. Windows: 1024×600/768 work area, 100/150/200/300% DPI, all eight languages.
   Resize, move between differently scaled monitors, scroll by wheel/trackpad/bar and
   Tab/Shift+Tab through every field and both buttons. Focus must scroll into view.
4. Make config.ini read-only or lock it against replacement. Save must report an error,
   keep the form/draft open, and not apply any runtime setting. Restore access and retry.
5. Set a **dummy** OPENAI_API_KEY environment variable. Open/Save Settings without typing
   a key: the field and persisted key remain empty, while AI still sees the fallback.
   An oversized environment value must be ignored safely. Never use real keys in captures.
6. Android: enable public-IP lookup, then disable and Save while a request is in flight.
   The address/detail must clear immediately; a late old result must not restore them.
7. Cache and permission actions are immediate utilities, not draft settings: verify cache
   counts refresh after clearing, and permission prompts do not accidentally save the form.
