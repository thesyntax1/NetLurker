#!/usr/bin/env python3
"""Generate the Android string resources for NetLurker from one catalog.

The desktop build keeps 687 catalog keys in eight INI files. The Android build needs the
same discipline but in resource form, so a single TSV holds every key for every language
and this script emits `res/values*/strings.xml`.

Two sources feed the output:

  1. `i18n/catalog.tsv` — every string the Android UI uses, authored for all 8 languages.
  2. `lang/*.ini`        — the desktop catalog, reused verbatim for the bad-port rule notes
                           so a rule reads identically on both platforms.

`--check` fails when a key used in Kotlin is missing from any locale, when a locale has an
empty value, or when the generated XML on disk differs from what would be generated. That
is the same contract as `tools/gen_lang.py --check` in the desktop build.

Usage:
    python3 android/tools/gen_strings.py            # write resources
    python3 android/tools/gen_strings.py --check    # verify, write nothing
"""

from __future__ import annotations

import argparse
import html
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ANDROID = os.path.join(ROOT, "android")
CATALOG = os.path.join(ANDROID, "i18n", "catalog.tsv")
LANG_DIR = os.path.join(ROOT, "lang")
RES_DIR = os.path.join(ANDROID, "app", "src", "main", "res")
KOTLIN_DIR = os.path.join(ANDROID, "app", "src", "main", "kotlin")
PORTS_KT = os.path.join(KOTLIN_DIR, "dev", "netlurker", "android", "core", "Ports.kt")

LOCALES = ["en", "tr", "es", "de", "fr", "ja", "zh", "pt"]
LOCALE_DIR = {"en": "values", **{code: f"values-{code}" for code in LOCALES if code != "en"}}

# Keys the code builds at runtime; each expansion must exist in the catalog.
DYNAMIC_KEYS = {
    "risk.level.{safe,info,warn,danger}": ["risk.level." + x for x in ("safe", "info", "warn", "danger")],
    "geo.status.{idle,pending,ok,failed,offline,disabled,unavailable}": [
        "geo.status." + x for x in ("idle", "pending", "ok", "failed", "offline", "disabled", "unavailable")
    ],
    "kpi.{...}": [
        "kpi." + x for x in ("download", "upload", "session_down", "session_up", "apps",
                             "active_apps", "destinations", "suspicious", "anomalies", "uptime")
    ],
}


def read_catalog() -> dict[str, dict[str, str]]:
    with open(CATALOG, encoding="utf-8") as handle:
        header = handle.readline().rstrip("\n").split("\t")
        assert header[0] == "key", f"catalog must start with a key column, got {header[0]!r}"
        languages = header[1:]
        if languages != LOCALES:
            raise SystemExit(f"catalog columns {languages} != expected {LOCALES}")
        out: dict[str, dict[str, str]] = {}
        for number, line in enumerate(handle, start=2):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) != 1 + len(LOCALES):
                raise SystemExit(f"{CATALOG}:{number}: expected {1 + len(LOCALES)} fields, got {len(parts)}")
            key = parts[0]
            if key in out:
                raise SystemExit(f"{CATALOG}:{number}: duplicate key {key}")
            out[key] = dict(zip(languages, parts[1:]))
        return out


def load_desktop_catalog() -> dict[str, dict[str, str]]:
    """lang/<code>.ini -> {english source: translation}."""
    tables: dict[str, dict[str, str]] = {}
    for code in LOCALES:
        path = os.path.join(LANG_DIR, f"{code}.ini")
        table: dict[str, str] = {}
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                table[key] = value
        tables[code] = table
    return tables


def port_notes() -> list[tuple[int, str]]:
    """Extract (port, english note) from Ports.kt so the table is never duplicated."""
    with open(PORTS_KT, encoding="utf-8") as handle:
        source = handle.read()
    block = source.split("val suspicious", 1)[1]
    block = block.split(")", 1)[1].split("/** Ports that are only alarming", 1)[0]
    pairs = re.findall(r"(\d+)\s+to\s+\(\d+\s+to\s+\"([^\"]+)\"\)", block)
    if len(pairs) < 30:
        raise SystemExit(f"only {len(pairs)} bad-port rules parsed from Ports.kt — parser drifted")
    return [(int(port), note) for port, note in pairs]


def add_port_entries(catalog: dict[str, dict[str, str]]) -> int:
    desktop = load_desktop_catalog()
    added = 0
    for port, note in port_notes():
        key = f"port_{port}"
        if key in catalog:
            continue
        row: dict[str, str] = {}
        for code in LOCALES:
            value = desktop[code].get(note)
            if value is None:
                raise SystemExit(
                    f"lang/{code}.ini has no entry for the bad-port note {note!r} "
                    f"(port {port}); the desktop catalog drifted"
                )
            row[code] = value
        catalog[key] = row
        added += 1
    return added


def escape(value: str) -> str:
    """Android resource escaping: apostrophes and quotes must be escaped, XML entities
    encoded, and the catalog's {placeholder} markers survive untouched."""
    text = html.escape(value, quote=False)
    text = text.replace("'", "\\'").replace('"', '\\"')
    text = text.replace("\\n", "\n")
    return text.strip()


def render(locale: str, catalog: dict[str, dict[str, str]]) -> str:
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        "<!-- Generated by android/tools/gen_strings.py from android/i18n/catalog.tsv.",
        "     Do not edit by hand: edit the catalog and re-run the generator. -->",
        "<resources>",
    ]
    for key in sorted(catalog):
        value = escape(catalog[key][locale])
        lines.append(f'    <string name="{key}">{value}</string>')
    lines.append("</resources>")
    lines.append("")
    return "\n".join(lines)


def used_keys() -> set[str]:
    """Every literal string key the Kotlin code asks for."""
    pattern = re.compile(r'(?:\bs|\bstrings\(\)|\blabel)\("([^"$]+)"')
    # AiClient substitutes catalog arguments through fill(label, "key", "name" to value).
    fill_pattern = re.compile(r'\bfill\([^,]+,\s*"([^"$]+)"')
    # ReasonKeys publishes the verdict reasons as constants that the UI resolves
    # indirectly, so their values count as usage too.
    const_pattern = re.compile(r'const val [A-Z0-9_]+\s*=\s*"(risk\.[a-z0-9_.]+)"')
    keys: set[str] = set()
    for directory, _, files in os.walk(KOTLIN_DIR):
        for name in files:
            if not name.endswith(".kt"):
                continue
            with open(os.path.join(directory, name), encoding="utf-8") as handle:
                source = handle.read()
            for matcher in (pattern, fill_pattern):
                for match in matcher.finditer(source):
                    key = match.group(1)
                    if key.startswith("port_"):
                        continue
                    keys.add(key)
            for match in const_pattern.finditer(source):
                keys.add(match.group(1))
    for expansions in DYNAMIC_KEYS.values():
        keys.update(expansions)
    return keys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="verify without writing")
    args = parser.parse_args()

    catalog = read_catalog()
    added = add_port_entries(catalog)
    print(f"catalog: {len(catalog) - added} authored keys + {added} port notes from lang/*.ini")

    problems: list[str] = []

    missing = sorted(used_keys() - set(catalog))
    for key in missing:
        problems.append(f"key used in Kotlin but absent from the catalog: {key}")

    for key, row in catalog.items():
        for locale, value in row.items():
            if not value.strip():
                problems.append(f"{key}: empty value for {locale}")

    # Placeholders must be identical in every language, or a translation would render
    # the raw {name} marker.
    for key, row in catalog.items():
        base = set(re.findall(r"\{[a-zA-Z0-9_]+\}", row["en"]))
        for locale, value in row.items():
            found = set(re.findall(r"\{[a-zA-Z0-9_]+\}", value))
            if base != found:
                problems.append(
                    f"{key}: {locale} placeholders {sorted(found)} != en {sorted(base)}"
                )

    unused = sorted(set(catalog) - used_keys() - {k for k in catalog if k.startswith("port_")}
                    - {"app_name", "notif_channel_name", "notif_channel_description",
                       "notif_anomaly_title", "notif_anomaly_body"})
    for key in unused:
        problems.append(f"catalog key never referenced from Kotlin: {key}")

    expected = {locale: render(locale, catalog) for locale in LOCALES}
    stale: list[str] = []
    for locale, content in expected.items():
        path = os.path.join(RES_DIR, LOCALE_DIR[locale], "strings.xml")
        current = None
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                current = handle.read()
        if current != content:
            stale.append(path)

    if args.check:
        for problem in problems:
            print("FAIL", problem)
        for path in stale:
            print("FAIL out of date:", os.path.relpath(path, ROOT))
        if problems or stale:
            print(f"\n{len(problems)} catalog problem(s), {len(stale)} stale file(s). "
                  "Run: python3 android/tools/gen_strings.py")
            return 1
        print(f"OK: {len(catalog)} keys x {len(LOCALES)} locales, all resources up to date")
        return 0

    if problems:
        for problem in problems:
            print("WARN", problem)
    for locale, content in expected.items():
        directory = os.path.join(RES_DIR, LOCALE_DIR[locale])
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "strings.xml"), "w", encoding="utf-8") as handle:
            handle.write(content)
    print(f"wrote {len(LOCALES)} strings.xml files ({len(catalog)} keys each)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
