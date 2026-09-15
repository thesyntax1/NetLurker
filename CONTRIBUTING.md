# Contributing

The first release needs trustworthy measurements and reproducible tests more than a long
feature list. Small, evidence-backed fixes are welcome.

## Before opening a change

1. Open an issue for a substantial feature. State which OS API/provider supplies the data.
2. Keep Windows and Android limitations explicit. Never substitute demo/estimated values
   for unavailable measurements, or label a provider failure as clean.
3. Add a regression test for changed arithmetic, parsing, caching or UI behavior.
4. Update the source catalogs, not generated XML/INI alone:
   `tools/lang_table.py` for desktop translations, `android/i18n/catalog.tsv` for Android.
5. Do not commit binaries, archives, API keys, keystores, device dumps, or raw network exports.

## Checks

```sh
python3 tools/gen_lang.py --check
python3 android/tools/gen_strings.py --check
python3 android/tools/check_symbols.py
python3 -m unittest discover -s tests -p 'test_*.py'
g++ -std=c++17 -Wall -Wextra -Werror -Isrc tests/ui_layout_test.cpp -o /tmp/layout-test
/tmp/layout-test
g++ -std=c++17 -Wall -Wextra -Werror -Isrc tests/evidence_rules_test.cpp src/json.cpp -o /tmp/evidence-test
/tmp/evidence-test
```

Build Windows with `build.bat` in an x64 VS developer prompt. For Android, run
`./gradlew testDebugUnitTest lintDebug assembleDebug` inside `android/`. A connected
emulator/device is required for `connectedDebugAndroidTest`; unit tests alone cannot prove
the UI renders. Record any checks you could not run.

A useful pull request includes the bug, its observable impact, the source of truth, tests
run, and screenshots only if they are actual redacted captures. Mark synthetic demo captures
as DEMO. Do not imply that an illustration is a functioning dashboard.
