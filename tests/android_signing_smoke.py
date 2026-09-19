#!/usr/bin/env python3
"""Android SDK integration fixture: ephemeral key/APK, never published or uploaded."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    version = json.loads((ROOT / "version.json").read_text())["version"]
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP")) as tmp:
        root = Path(tmp)
        keystore = root / "fixture.jks"
        env = {**os.environ, "FIXTURE_PASSWORD": "disposable-ci-fixture-not-a-production-secret"}
        subprocess.run(["keytool", "-genkeypair", "-noprompt", "-keystore", str(keystore),
                        "-storepass:env", "FIXTURE_PASSWORD", "-keypass:env", "FIXTURE_PASSWORD",
                        "-alias", "fixture", "-dname", "CN=NetLurker CI fixture - not for distribution",
                        "-keyalg", "RSA", "-keysize", "2048", "-validity", "1"], env=env, check=True)
        certificate = subprocess.check_output(["keytool", "-exportcert", "-keystore", str(keystore),
                                               "-storepass:env", "FIXTURE_PASSWORD", "-alias", "fixture"], env=env)
        env.update(ANDROID_KEYSTORE_BASE64=base64.b64encode(keystore.read_bytes()).decode(),
                   ANDROID_KEYSTORE_PASSWORD=env["FIXTURE_PASSWORD"], ANDROID_KEY_PASSWORD=env["FIXTURE_PASSWORD"],
                   ANDROID_KEY_ALIAS="fixture", ANDROID_SIGNING_CERT_SHA256=hashlib.sha256(certificate).hexdigest())
        subprocess.run([sys.executable, str(ROOT / "tools/sign_android.py"),
                        "--input", str(ROOT / "android/app/build/outputs/apk/release"),
                        "--output", str(root / "output"), "--version", version, "--revision", revision], env=env, check=True)
    print("PASS: release APK alignment/signature/identity/version verified with a disposable fixture key; fixture files deleted, not distributed.")


if __name__ == "__main__":
    main()
