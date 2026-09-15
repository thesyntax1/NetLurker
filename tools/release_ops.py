#!/usr/bin/env python3
"""Release preflight, manifest and conservative GitHub asset publication.

Uses the already authenticated gh CLI. No token is accepted as an argument or logged.
Existing release files are NEVER overwritten; retry only accepts identical bytes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile
from urllib.parse import quote

from release_version import version_info


def gh(*args: str, data: dict | None = None, binary: bool = False):
    command = ["gh", *args]
    if data is not None:
        command += ["--input", "-"]
    result = subprocess.run(command, input=json.dumps(data).encode() if data is not None else None,
                            check=True, stdout=subprocess.PIPE)
    return result.stdout if binary else json.loads(result.stdout or b"null")


def api(path: str, **kwargs):
    return gh("api", path, **kwargs)


def tag_version(tag: str) -> dict:
    if not tag.startswith("v"):
        raise ValueError("Release tag must start with v, e.g. v6.0.1 or v6.0.1-rc.1")
    return version_info(tag[1:])


def tag_revision(repo: str, tag: str) -> str:
    obj = api(f"repos/{repo}/git/ref/tags/{quote(tag, safe='')}")["object"]
    for _ in range(10):
        if obj["type"] == "commit":
            if not re.fullmatch(r"[0-9a-f]{40}", obj["sha"]):
                raise ValueError("Invalid commit SHA")
            return obj["sha"]
        if obj["type"] != "tag":
            break
        obj = api(f"repos/{repo}/git/tags/{obj['sha']}")["object"]
    raise ValueError("Release tag does not resolve to a commit")


def check_release(release: dict, tag: str, release_id: int | None = None):
    info = tag_version(tag)
    if release.get("tag_name") != tag or release.get("draft") is not False:
        raise ValueError("Publish the matching release first; draft releases are not upload targets")
    if bool(release.get("prerelease")) != ("-" in info["version"]):
        raise ValueError("Prerelease checkbox must match the tag: -alpha.N, -beta.N and -rc.N are prereleases")
    if release_id is not None and release.get("id") != release_id:
        raise ValueError("Release was deleted/recreated while the build ran; refusing a different target")


def signing_policy(env: dict) -> tuple[bool, bool]:
    def complete(names):
        present = [bool(env.get(name, "").strip()) for name in names]
        if any(present) and not all(present):
            raise ValueError("Incomplete signing configuration. Configure all of: " + ", ".join(names))
        return all(present)
    android = complete(("ANDROID_KEYSTORE_BASE64", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_ALIAS", "ANDROID_KEY_PASSWORD"))
    windows = complete(("WINDOWS_CERT_BASE64", "WINDOWS_CERT_PASSWORD"))
    if android and not re.fullmatch(r"[0-9a-fA-F]{64}", env.get("ANDROID_SIGNING_CERT_SHA256", "").replace(":", "")):
        raise ValueError("Set ANDROID_SIGNING_CERT_SHA256 to the expected release certificate SHA-256 fingerprint")
    if env.get("REQUIRE_ANDROID_RELEASE", "").lower() == "true" and not android:
        raise ValueError("Android publication is required but the release signing secrets are missing")
    if env.get("REQUIRE_WINDOWS_SIGNATURE", "").lower() == "true" and not windows:
        raise ValueError("Windows signing is required but certificate secrets are missing")
    return android, windows


def preflight(tag: str, publish: bool):
    info = tag_version(tag)
    repo = os.environ["GITHUB_REPOSITORY"]
    release_id = ""
    revision = os.environ["GITHUB_SHA"]
    if publish:
        release = api(f"repos/{repo}/releases/tags/{quote(tag, safe='')}")
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        expected_id = event.get("release", {}).get("id")
        check_release(release, tag, expected_id)
        release_id = release["id"]
        revision = tag_revision(repo, tag)
        if os.environ.get("GITHUB_EVENT_NAME") == "release" and revision != os.environ["GITHUB_SHA"]:
            raise ValueError("Tag moved after the release event")
    android, windows = signing_policy(os.environ)
    values = {**info, "tag": tag, "revision": revision, "release_id": release_id,
              "publish": str(publish).lower(), "android": str(android).lower(), "windows_signed": str(windows).lower()}
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
        for key, value in values.items():
            out.write(f"{key}={value}\n")
    print(f"Version {info['version']}; source {revision}; Android {'signed APK' if android else 'omitted (no key configured)'}; "
          f"Windows {'signed' if windows else 'UNSIGNED'}; publish={publish}")


def verify_input(source: Path, version: str, revision: str):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Expected a full source SHA")
    if (source / "build-revision.txt").read_text(encoding="utf-8-sig").strip() != revision:
        raise ValueError("Artifact was built from a different revision")
    if json.loads((source / "build-version.json").read_text(encoding="utf-8-sig")) != version_info(version):
        raise ValueError("Artifact was built with a different version")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        return digest.hexdigest()


def manifest(directory: Path, version: str, revision: str, android: bool, run_url: str):
    info = version_info(version)
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Expected full source SHA")
    prefix = f"NetLurker-v{version}"
    expected = {f"{prefix}-win64.zip", f"{prefix}-setup.exe", "windows-signatures.json"}
    if android:
        expected |= {f"{prefix}-android.apk", "android-signature.json"}
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError("Release inputs are incomplete or include unexpected files")
    signatures = {}
    for name in ("windows-signatures.json", "android-signature.json"):
        if (directory / name).exists():
            report = json.loads((directory / name).read_text(encoding="utf-8-sig"))
            if report.get("version") != version or report.get("source_revision") != revision:
                raise ValueError("Signature report version/revision mismatch")
            signatures[name] = report
    windows = signatures["windows-signatures.json"].get("files", [])
    if len(windows) != 2 or {item.get("name") for item in windows} != {"NetLurker.exe", f"{prefix}-setup.exe"}:
        raise ValueError("Incomplete Windows signature report")
    with zipfile.ZipFile(directory / f"{prefix}-win64.zip") as archive:
        if archive.getinfo("NetLurker.exe").file_size > 64 * 1024 * 1024:
            raise ValueError("Unexpected executable size")
        exe_digest = hashlib.sha256(archive.read("NetLurker.exe")).hexdigest()
    for item in windows:
        expected_hash = exe_digest if item["name"] == "NetLurker.exe" else sha256(directory / item["name"])
        status, certificate = item.get("status"), item.get("certificate_sha256")
        if item.get("sha256") != expected_hash or status not in ("Valid", "NotSigned"):
            raise ValueError("Windows signature report does not match payload/status")
        if (status == "Valid" and not re.fullmatch(r"[0-9a-f]{64}", certificate or "")) or (status == "NotSigned" and certificate is not None):
            raise ValueError("Windows signer certificate/status mismatch")
    if android:
        report = signatures["android-signature.json"]
        apk = f"{prefix}-android.apk"
        if (report.get("status") != "verified" or report.get("file") != apk
                or report.get("sha256") != sha256(directory / apk)
                or not re.fullmatch(r"[0-9a-f]{64}", report.get("certificate_sha256", ""))):
            raise ValueError("Android signature report does not match payload/status")
    payload = {**info, "source_revision": revision, "build_url": run_url,
               "version_stamping": "tools/release_version.py applied before compilation; tag is not moved",
               "android": "signed" if android else "omitted: production signing not configured",
               "signatures": signatures,
               "files": [{"name": name, "sha256": sha256(directory / name), "bytes": (directory / name).stat().st_size}
                         for name in sorted(expected)]}
    (directory / "RELEASE-MANIFEST.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    expected.add("RELEASE-MANIFEST.json")
    (directory / "SHA256SUMS.txt").write_text("".join(f"{sha256(directory / name)}  {name}\n" for name in sorted(expected)), encoding="ascii")
    return payload


def verify_bundle(directory: Path) -> dict:
    if any(p.is_symlink() or not p.is_file() for p in directory.iterdir()):
        raise ValueError("Release bundle must contain ordinary files only")
    payload = json.loads((directory / "RELEASE-MANIFEST.json").read_text())
    version_info(payload["version"])
    rows = (directory / "SHA256SUMS.txt").read_text().splitlines()
    entries = {}
    for row in rows:
        if not re.fullmatch(r"[0-9a-f]{64}  [A-Za-z0-9.-]+", row):
            raise ValueError("Invalid checksum entry")
        digest, name = row.split("  ", 1)
        if name in entries or name in (".", "..", "SHA256SUMS.txt"):
            raise ValueError("Duplicate/invalid checksum name")
        entries[name] = digest
    if set(entries) | {"SHA256SUMS.txt"} != {p.name for p in directory.iterdir()}:
        raise ValueError("Missing or extra release files")
    for name, digest in entries.items():
        path = directory / name
        if path.is_symlink() or not path.is_file() or sha256(path) != digest:
            raise ValueError(f"Release checksum mismatch: {name}")
    recorded = {item["name"]: item["sha256"] for item in payload["files"]}
    if recorded != {name: digest for name, digest in entries.items() if name != "RELEASE-MANIFEST.json"}:
        raise ValueError("Manifest/checksum mismatch")
    return payload


def assets(repo: str, release_id: int) -> list[dict]:
    result = []
    for page in range(1, 101):
        batch = api(f"repos/{repo}/releases/{release_id}/assets?per_page=100&page={page}")
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise ValueError("Too many release assets")


def asset_digest(repo: str, asset: dict) -> str:
    digest = asset.get("digest") or ""
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        return digest[7:]
    # Older GitHub assets may have no digest. Verify bytes instead of guessing.
    data = gh("api", f"repos/{repo}/releases/assets/{asset['id']}", "-H", "Accept: application/octet-stream", binary=True)
    return hashlib.sha256(data).hexdigest()


def plan_upload(local: dict[str, str], existing: list[dict], digest) -> list[str]:
    by_name = {}
    for asset in existing:
        if asset["name"] in by_name:
            raise ValueError("Duplicate remote asset names")
        by_name[asset["name"]] = asset
    missing = []
    for name, checksum in sorted(local.items()):
        if name not in by_name:
            missing.append(name)
        elif by_name[name].get("state") != "uploaded" or digest(by_name[name]) != checksum:
            raise ValueError(f"Existing release asset differs or is incomplete: {name}. Refusing overwrite; use a new version or review the failed upload.")
    return missing


START, END = "<!-- netlurker-assets:start -->", "<!-- netlurker-assets:end -->"


def release_notes(body: str, payload: dict) -> str:
    unsigned = any(entry.get("status") != "Valid" for entry in payload["signatures"]["windows-signatures.json"]["files"])
    section = (f"{START}\n## Downloads and verification\n\n"
               f"- Version: **{payload['version']}**; source: `{payload['source_revision']}`.\n"
               f"- [Build and test run]({payload['build_url']}). See `RELEASE-MANIFEST.json` for file hashes and signing identities.\n"
               "- Windows: portable `-win64.zip` (extract the whole ZIP, including `lang/`) or `-setup.exe`.\n"
               f"- Windows Authenticode: **{'UNSIGNED — SmartScreen may warn; do not disable security protections' if unsigned else 'verified by the release job'}**.\n"
               f"- Android: **{payload['android']}**. Only the production-signed APK is a public download; no debug or unsigned APK is substituted.\n"
               "- Verify downloads against `SHA256SUMS.txt` (`sha256sum -c SHA256SUMS.txt` or PowerShell `Get-FileHash -Algorithm SHA256`). Hashes do not replace code signing.\n"
               "- CI success is not a physical-device/provider audit. Review `docs/RELEASE-CHECKLIST.md` for remaining manual checks.\n"
               f"{END}")
    if START in body or END in body:
        if body.count(START) != 1 or body.count(END) != 1 or body.index(START) > body.index(END):
            raise ValueError("Malformed managed release-notes section")
        return body[:body.index(START)] + section + body[body.index(END) + len(END):]
    return body.rstrip() + "\n\n" + section + "\n"


def publish(directory: Path, tag: str, revision: str, release_id: int):
    repo = os.environ["GITHUB_REPOSITORY"]
    payload = verify_bundle(directory)
    if payload["source_revision"] != revision or payload["version"] != tag_version(tag)["version"]:
        raise ValueError("Bundle does not match requested release")
    def target():
        release = api(f"repos/{repo}/releases/{release_id}")
        check_release(release, tag, release_id)
        if tag_revision(repo, tag) != revision:
            raise ValueError("Tag moved during the build; refusing upload")
        return release
    target()
    local = {p.name: sha256(p) for p in directory.iterdir()}
    missing = plan_upload(local, assets(repo, release_id), lambda asset: asset_digest(repo, asset))
    for name in missing:
        target()
        # Address the immutable release ID, not a fresh tag lookup, so a concurrent
        # delete/recreate cannot redirect an upload to a different release.
        url = f"https://uploads.github.com/repos/{repo}/releases/{release_id}/assets?name={quote(name, safe='')}"
        gh("api", url, "--method", "POST", "-H", "Content-Type: application/octet-stream",
           "--input", str(directory / name))
    if plan_upload(local, assets(repo, release_id), lambda asset: asset_digest(repo, asset)):
        raise ValueError("Uploaded asset verification incomplete")
    release = target()
    gh("api", f"repos/{repo}/releases/{release_id}", "--method", "PATCH",
       data={"body": release_notes(release.get("body") or "", payload)})
    print(f"Verified {len(local)} assets on release {tag}; no existing bytes were overwritten.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--tag", required=True)
    p.add_argument("--publish", choices=("true", "false"), required=True)
    p = sub.add_parser("verify-input")
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--revision", required=True)
    p = sub.add_parser("manifest")
    p.add_argument("--directory", type=Path, required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--revision", required=True)
    p.add_argument("--android", choices=("true", "false"), required=True)
    p.add_argument("--run-url", required=True)
    p = sub.add_parser("publish")
    p.add_argument("--directory", type=Path, required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--revision", required=True)
    p.add_argument("--release-id", type=int, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        preflight(args.tag, args.publish == "true")
    elif args.command == "verify-input":
        verify_input(args.input, args.version, args.revision)
    elif args.command == "manifest":
        manifest(args.directory, args.version, args.revision, args.android == "true", args.run_url)
        verify_bundle(args.directory)
    else:
        publish(args.directory, args.tag, args.revision, args.release_id)
