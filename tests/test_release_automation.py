"""Offline regressions. Mocked upload tests do not publish anything on GitHub."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from release_version import version_info, stamp
from release_ops import (tag_version, tag_revision, signing_policy, check_release, verify_input,
                         manifest, verify_bundle, plan_upload, release_notes, publish, START, END)
from sign_android import verify_badging, verify_certificate

SHA = "a" * 40


class VersionTest(unittest.TestCase):
    def test_invalid_or_injectable_tags_are_rejected(self):
        for tag in ("6.0.1", "v01.0.0", "v6.0", "v6.0.0+build", "v6.0.0-rc.0", "v6.0.0-rc.200",
                    "v210.0.0", "v6.100.0", "v6.0.100", "v6.0.0;echo hi", "v6.0.0\nGITHUB_TOKEN=oops"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                tag_version(tag)

    def test_android_codes_order_prereleases_and_updates(self):
        versions = ["6.0.0-alpha.1", "6.0.0-alpha.199", "6.0.0-beta.1", "6.0.0-beta.199",
                    "6.0.0-rc.1", "6.0.0-rc.199", "6.0.0", "6.0.1-alpha.1", "6.0.99", "6.1.0-alpha.1",
                    "6.99.99", "7.0.0-alpha.1", "209.99.99"]
        codes = [version_info(v)["android_version_code"] for v in versions]
        self.assertEqual(sorted(set(codes)), codes)
        self.assertGreater(version_info("0.0.0-alpha.1")["android_version_code"], 0)
        self.assertLessEqual(codes[-1], 2100000000)

    def test_stamping_updates_both_numeric_and_display_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "res").mkdir()
            shutil.copyfile(ROOT / "res/netlurker.rc", root / "res/netlurker.rc")
            info = stamp(root, "6.1.2-rc.4")
            text = (root / "res/netlurker.rc").read_text()
            self.assertIn('FILEVERSION 6,1,2,404', text)
            self.assertIn('VALUE "ProductVersion", "6.1.2-rc.4"', text)
            self.assertEqual(info, json.loads((root / "version.json").read_text()))
            self.assertEqual(stamp(root, "6.1.2-rc.4"), info)


class PolicyTest(unittest.TestCase):
    def test_no_keys_omits_android_and_discloses_unsigned_windows(self):
        self.assertEqual(signing_policy({}), (False, False))
        for name in ("REQUIRE_ANDROID_RELEASE", "REQUIRE_WINDOWS_SIGNATURE"):
            with self.assertRaises(ValueError):
                signing_policy({name: "true"})

    def test_partial_keys_or_missing_fingerprint_fail_closed(self):
        for env in ({"WINDOWS_CERT_BASE64": "placeholder"}, {"ANDROID_KEY_ALIAS": "placeholder"}):
            with self.assertRaises(ValueError):
                signing_policy(env)
        env = {key: "fixture" for key in ("ANDROID_KEYSTORE_BASE64", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_ALIAS", "ANDROID_KEY_PASSWORD")}
        with self.assertRaises(ValueError):
            signing_policy(env)
        env["ANDROID_SIGNING_CERT_SHA256"] = "a" * 64
        self.assertEqual(signing_policy(env), (True, False))

    def test_release_identity_and_prerelease_flag_are_checked(self):
        release = {"id": 7, "tag_name": "v6.0.1-rc.1", "draft": False, "prerelease": True}
        check_release(release, release["tag_name"], 7)
        for change in ({"draft": True}, {"id": 8}, {"prerelease": False}, {"tag_name": "v6.0.1"}):
            with self.assertRaises(ValueError):
                check_release({**release, **change}, "v6.0.1-rc.1", 7)

    def test_lightweight_and_annotated_tags_resolve_to_exact_commit(self):
        with patch("release_ops.api", return_value={"object": {"type": "commit", "sha": SHA}}):
            self.assertEqual(tag_revision("owner/repo", "v6.0.1"), SHA)
        with patch("release_ops.api", side_effect=[{"object": {"type": "tag", "sha": "b" * 40}},
                                                   {"object": {"type": "commit", "sha": SHA}}]):
            self.assertEqual(tag_revision("owner/repo", "v6.0.1"), SHA)

    def test_android_identity_and_debug_flags_are_not_guessed(self):
        info = version_info("6.0.1")
        text = f"package: name='dev.netlurker.android' versionCode='{info['android_version_code']}' versionName='6.0.1' platformBuildVersionName='15'\n"
        verify_badging(text, "6.0.1")
        for invalid in (text.replace(".android'", ".android.debug'"), text + "application-debuggable", text.replace("6.0.1", "6.0.0")):
            with self.assertRaises(ValueError):
                verify_badging(invalid, "6.0.1")

    def test_wrong_or_debug_certificate_is_rejected(self):
        text = "Signer #1 certificate SHA-256 digest: " + "a" * 64 + "\n"
        self.assertEqual(verify_certificate(text, "AA:" * 31 + "AA"), "a" * 64)
        self.assertEqual(verify_certificate(text.rstrip() + "  \t\n", "a" * 64), "a" * 64)
        for invalid in (text.replace("a", "b"), text + text, text + "Signer #1 certificate DN: CN=Android Debug, O=Android\n"):
            with self.assertRaises(ValueError):
                verify_certificate(invalid, "a" * 64)

    def test_modern_sdk_scheme_label_preserves_certificate_pinning(self):
        text = "Number of signers: 1\nV3.0 Signer: certificate SHA-256 digest: " + "a" * 64 + "\n"
        self.assertEqual(verify_certificate(text, "a" * 64), "a" * 64)
        for invalid in (text.replace("signers: 1", "signers: 2"),
                        text.replace("certificate SHA-256", "public key SHA-256"),
                        text.replace("V3.0 Signer:", "Source Stamp Signer")):
            with self.assertRaises(ValueError):
                verify_certificate(invalid, "a" * 64)

    def test_artifact_marker_must_match_version_and_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "build-revision.txt").write_text(SHA)
            (root / "build-version.json").write_text(json.dumps(version_info("6.0.1")))
            verify_input(root, "6.0.1", SHA)
            for version, sha in (("6.0.2", SHA), ("6.0.1", "b" * 40)):
                with self.assertRaises(ValueError):
                    verify_input(root, version, sha)


class BundleTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.exe = b"synthetic exe fixture, not a runnable binary"
        with zipfile.ZipFile(self.root / "NetLurker-v6.0.1-win64.zip", "w") as archive:
            archive.writestr("NetLurker.exe", self.exe)
        installer = self.root / "NetLurker-v6.0.1-setup.exe"
        installer.write_bytes(b"synthetic installer fixture")
        report = {"version": "6.0.1", "source_revision": SHA, "files": [
            {"name": "NetLurker.exe", "sha256": hashlib.sha256(self.exe).hexdigest(), "status": "NotSigned", "certificate_sha256": None},
            {"name": installer.name, "sha256": hashlib.sha256(installer.read_bytes()).hexdigest(), "status": "NotSigned", "certificate_sha256": None}]}
        (self.root / "windows-signatures.json").write_text(json.dumps(report))

    def bundle(self):
        return manifest(self.root, "6.0.1", SHA, False, "https://example.invalid/run/1")

    def test_bundle_hashes_and_unsigned_disclosure(self):
        payload = self.bundle()
        self.assertEqual(verify_bundle(self.root), payload)
        notes = release_notes("Maintainer's original notes", payload)
        self.assertIn("UNSIGNED", notes)
        self.assertIn("omitted", notes)
        self.assertTrue(notes.startswith("Maintainer's original notes"))
        self.assertEqual(release_notes(notes, payload), notes)
        with self.assertRaises(ValueError):
            release_notes(START + START + END, payload)

    def test_tampered_extra_or_missing_payloads_are_rejected(self):
        self.bundle()
        file = self.root / "NetLurker-v6.0.1-setup.exe"
        file.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            verify_bundle(self.root)
        file.unlink()
        with self.assertRaises(ValueError):
            verify_bundle(self.root)

    def test_signature_report_cannot_claim_another_executable(self):
        report = json.loads((self.root / "windows-signatures.json").read_text())
        report["files"][0]["sha256"] = "0" * 64
        (self.root / "windows-signatures.json").write_text(json.dumps(report))
        with self.assertRaises(ValueError):
            self.bundle()

    def test_android_requested_but_missing_does_not_succeed(self):
        with self.assertRaises(ValueError):
            manifest(self.root, "6.0.1", SHA, True, "https://example.invalid/run/1")

    def test_mocked_publish_uploads_verifies_and_patches_notes_without_clobber(self):
        self.bundle()
        remote = []
        release = {"id": 7, "tag_name": "v6.0.1", "draft": False, "prerelease": False, "body": "Human release notes"}
        def fake_api(path):
            if "/assets?" in path:
                return remote.copy()
            return release.copy()
        def fake_gh(*args, **kwargs):
            if args[0] == "api" and args[1].startswith("https://uploads.github.com/"):
                self.assertIn("/releases/7/assets?name=", args[1])
                self.assertEqual(args[2:4], ("--method", "POST"))
                path = Path(args[-1])
                self.assertNotIn("--clobber", args)
                remote.append({"name": path.name, "state": "uploaded", "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()})
            else:
                self.assertEqual(args[-2:], ("--method", "PATCH"))
                self.assertTrue(kwargs["data"]["body"].startswith("Human release notes"))
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}), patch("release_ops.api", side_effect=fake_api), \
             patch("release_ops.gh", side_effect=fake_gh) as calls, patch("release_ops.tag_revision", return_value=SHA):
            publish(self.root, "v6.0.1", SHA, 7)
            self.assertEqual(len(remote), 5)
            calls.reset_mock()
            publish(self.root, "v6.0.1", SHA, 7)
            self.assertEqual(calls.call_count, 1)  # Same bytes: only managed notes are refreshed.

    def test_moved_tag_blocks_all_uploads(self):
        self.bundle()
        release = {"id": 7, "tag_name": "v6.0.1", "draft": False, "prerelease": False}
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}), patch("release_ops.api", return_value=release), \
             patch("release_ops.tag_revision", return_value="b" * 40), patch("release_ops.gh") as calls:
            with self.assertRaises(ValueError):
                publish(self.root, "v6.0.1", SHA, 7)
            calls.assert_not_called()


class UploadPlanTest(unittest.TestCase):
    def test_identical_assets_are_skipped_and_missing_assets_uploaded(self):
        existing = [{"name": "old.zip", "state": "uploaded", "digest": "same"}]
        self.assertEqual(plan_upload({"old.zip": "same", "new.zip": "new"}, existing, lambda a: a["digest"]), ["new.zip"])

    def test_conflicts_and_partial_uploads_never_get_overwritten(self):
        for state, digest in (("uploaded", "different"), ("starter", "same")):
            with self.assertRaises(ValueError):
                plan_upload({"app.zip": "same"}, [{"name": "app.zip", "state": state, "digest": digest}], lambda a: a["digest"])

    def test_duplicate_remote_names_are_rejected(self):
        asset = {"name": "app.zip", "state": "uploaded", "digest": "same"}
        with self.assertRaises(ValueError):
            plan_upload({"app.zip": "same"}, [asset, asset], lambda a: a["digest"])


if __name__ == "__main__":
    unittest.main()
