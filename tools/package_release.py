#!/usr/bin/env python3
"""Package a freshly tested Windows artifact. Does not build, sign, tag or publish.

The input artifact must carry the exact source revision written by the build job.
Outputs are staged separately so a tracked/stale executable cannot masquerade as a build.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
import zipfile
from pathlib import Path

from release_ops import verify_input
from release_version import version_info

ROOT = Path(__file__).resolve().parents[1]
LANGUAGES = ("en", "tr", "es", "de", "fr", "ja", "zh", "pt")


def package(source: Path, output: Path, version: str, revision: str, public: bool = False) -> Path:
    version_info(version)
    verify_input(source, version, revision)
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("revision must be the full source commit SHA")
    if (source / "build-revision.txt").read_text().strip() != revision:
        raise ValueError("artifact revision does not match the requested source revision")
    exe = source / "NetLurker.exe"
    data = exe.read_bytes()
    if len(data) < 256 or data[:2] != b"MZ":
        raise ValueError("not a PE executable")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 6 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    if struct.unpack_from("<H", data, pe + 4)[0] != 0x8664:
        raise ValueError("only Windows x64 artifacts are supported")
    resource = (ROOT / "res/netlurker.rc").read_text()
    match = re.search(r"FILEVERSION\s+(\d+),(\d+),(\d+),", resource)
    if not match or version.split("-", 1)[0] != ".".join(match.groups()):
        raise ValueError("version does not match the Windows resource version")
    payload = {"NetLurker.exe": data}
    for code in LANGUAGES:
        path = source / "lang" / f"{code}.ini"
        content = path.read_bytes()
        if content != (ROOT / "lang" / path.name).read_bytes():
            raise ValueError(f"missing or stale bundled language: {code}")
        payload[f"lang/{path.name}"] = content
    for name in ("LICENSE", "README.md", "README.tr.md", "PRIVACY.md", "SECURITY.md", "CONTRIBUTING.md",
                 "android/README-android.md", "docs/DATA-ACCURACY.md", "docs/RELEASE-CHECKLIST.md", "docs/RELEASES.md",
                 "docs/UI-REGRESSION-CHECKS.md", "docs/VISUAL-PROVENANCE.md"):
        payload[name] = (ROOT / name).read_bytes()
    payload["BUILDINFO.json"] = (json.dumps({
        "version": version, "source_revision": revision,
        "repository": "https://github.com/thesyntax1/NetLurker",
        "platform": "windows-x64", "channel": "release" if public else "release-candidate",
        "version_stamping": "tools/release_version.py applied before compilation",
        "signature": "not verified by packager; see external windows-signatures.json or verify Authenticode locally",
    }, indent=2) + "\n").encode()
    sums = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(payload.items()))
    payload["SHA256SUMS.txt"] = sums.encode()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"NetLurker-v{version}-win64.zip"
    if archive.exists():
        raise FileExistsError(f"refusing to overwrite an existing candidate: {archive}")
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in sorted(payload.items()):
            # Stable container metadata; this does not assert that the compiler is reproducible.
            entry = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(entry, content)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / "SHA256SUMS.txt").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    return archive


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--public", action="store_true", help="Label metadata as release, not candidate; does NOT upload or attest a signature")
    args = parser.parse_args()
    print(package(args.input, args.output, args.version, args.revision, args.public))
