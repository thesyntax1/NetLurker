#!/usr/bin/env python3
"""Sign only the exact tested release APK; keystore/passwords are environment-only.

Requires Android SDK build-tools (zipalign, apksigner, aapt2). The expected public
certificate fingerprint is pinned separately from secrets to catch key rotation.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from release_ops import verify_input
from release_version import version_info


def verify_badging(text: str, version: str):
    info = version_info(version)
    match = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", text, re.M)
    if not match or match.groups() != ("dev.netlurker.android", str(info["android_version_code"]), version):
        raise ValueError("APK application ID / embedded version does not match the release")
    if "application-debuggable" in text:
        raise ValueError("Debuggable APK must not be published")


def verify_certificate(text: str, expected: str) -> str:
    # New SDKs label the selected scheme "V3.0 Signer:"; older ones use
    # "Signer #1". Accept both exact formats, never public-key/SourceStamp hashes.
    counts = re.findall(r"^Number of signers:[ \t]*([0-9]+)[ \t]*$", text, re.M)
    if counts and counts != ["1"]:
        raise ValueError("Exactly one APK signer is required")
    matches = re.findall(r"^(?:Signer #[0-9]+|V[1-4](?:\.[0-9]+)? Signer:) certificate SHA-256 digest:[ \t]*([0-9a-fA-F]{64})[ \t]*$", text, re.M)
    if len(matches) != 1 or matches[0].lower() != expected.replace(":", "").lower():
        raise ValueError(f"APK signer differs from ANDROID_SIGNING_CERT_SHA256: expected {expected}, parsed {matches}")
    if re.search(r"CN=Android Debug(?:,|$)", text, re.M):
        raise ValueError("Android debug certificate cannot be a production signing identity")
    return matches[0].lower()


def sign(source: Path, output: Path, version: str, revision: str):
    verify_input(source, version, revision)
    apks = list(source.glob("*.apk"))
    if len(apks) != 1:
        raise ValueError("Expected exactly one release APK")
    sdk = Path(os.environ["ANDROID_HOME"]) / "build-tools"
    versions = [p for p in sdk.iterdir() if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", p.name)]
    tools = max(versions, key=lambda p: tuple(map(int, p.name.split("."))))
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"NetLurker-v{version}-android.apk"
    if destination.exists():
        raise FileExistsError("Refusing to overwrite an APK")
    def run(tool, *args):
        return subprocess.check_output([str(tools / tool), *map(str, args)], text=True)
    with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP")) as temp:
        key = Path(temp) / "release.keystore"
        key.write_bytes(base64.b64decode("".join(os.environ["ANDROID_KEYSTORE_BASE64"].split()), validate=True))
        key.chmod(0o600)
        aligned = Path(temp) / "aligned.apk"
        run("zipalign", "-f", "-p", "4", apks[0], aligned)
        run("apksigner", "sign", "--ks", key, "--ks-key-alias", os.environ["ANDROID_KEY_ALIAS"],
            "--ks-pass", "env:ANDROID_KEYSTORE_PASSWORD", "--key-pass", "env:ANDROID_KEY_PASSWORD",
            "--v4-signing-enabled", "false", "--out", destination, aligned)
        verification = run("apksigner", "verify", "--verbose", "--print-certs", destination)
        print(verification, flush=True)  # Public certificate/verification data only, no key material.
        fingerprint = verify_certificate(verification, os.environ["ANDROID_SIGNING_CERT_SHA256"])
        run("zipalign", "-c", "-p", "4", destination)
        verify_badging(run("aapt2", "dump", "badging", destination), version)
        report = {"version": version, "source_revision": revision, "status": "verified",
                  "certificate_sha256": fingerprint, "file": destination.name,
                  "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}
        (output / "android-signature.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"Verified release-format APK {destination.name}; certificate SHA-256: {fingerprint}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    sign(args.input, args.output, args.version, args.revision)
