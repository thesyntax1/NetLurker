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
- Change language while paused: toolbar labels and hit regions should update immediately.
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
