#!/usr/bin/env python3
"""One release version policy for Windows, Android and asset names.

Public tags: vMAJOR.MINOR.PATCH[-alpha.N|-beta.N|-rc.N]. Bounds leave room
for monotonically increasing Android versionCodes below Play's 2,100,000,000.
Release CI stamps a working copy before compiling; it never commits or moves tags.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def version_info(version: str) -> dict:
    match = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(alpha|beta|rc)\.([1-9][0-9]*))?", version)
    if not match:
        raise ValueError("Use MAJOR.MINOR.PATCH, optionally -alpha.N, -beta.N or -rc.N (no leading v)")
    major, minor, patch = map(int, match.group(1, 2, 3))
    stage, number = match.group(4, 5)
    if major > 209 or minor > 99 or patch > 99 or (number and int(number) > 199):
        raise ValueError("Version bounds: major 0..209; minor/patch 0..99; prerelease number 1..199")
    rank = {"alpha": 0, "beta": 200, "rc": 400}[stage] + int(number) if stage else 999
    return {"version": version, "android_version_code": major * 10000000 + minor * 100000 + patch * 1000 + rank,
            "windows_version": f"{major}.{minor}.{patch}.{rank}"}


def stamp(root: Path, version: str) -> dict:
    info = version_info(version)
    resource = root / "res/netlurker.rc"
    text = resource.read_text(encoding="utf-8")
    for field in ("FILEVERSION", "PRODUCTVERSION"):
        text, count = re.subn(rf"(?m)^{field} [0-9,]+$", field + " " + info["windows_version"].replace(".", ","), text)
        if count != 1:
            raise ValueError(f"Expected exactly one {field}")
    for field in ("FileVersion", "ProductVersion"):
        text, count = re.subn(rf'(VALUE "{field}", )"[^"]+"', rf'\g<1>"{version}"', text)
        if count != 1:
            raise ValueError(f"Expected exactly one {field}")
    resource.write_text(text, encoding="utf-8")
    (root / "version.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    return info


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="", help="Empty uses the committed version.json")
    args = parser.parse_args()
    version = args.version or json.loads((ROOT / "version.json").read_text())["version"]
    info = stamp(ROOT, version)
    print(json.dumps(info))
