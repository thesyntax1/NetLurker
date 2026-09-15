import hashlib
import json
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from package_release import package, LANGUAGES
from check_smoke import verify


class PackageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "input"
        (self.source / "lang").mkdir(parents=True)
        self.revision = "a" * 40
        (self.source / "build-revision.txt").write_text(self.revision)
        # Synthetic PE fixture, never distributed or passed off as an executable build.
        data = bytearray(256)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3c, 128)
        data[128:132] = b"PE\0\0"
        struct.pack_into("<H", data, 132, 0x8664)
        (self.source / "NetLurker.exe").write_bytes(data)
        for code in LANGUAGES:
            shutil.copyfile(ROOT / "lang" / f"{code}.ini", self.source / "lang" / f"{code}.ini")

    def build(self, revision=None, version="6.0.0-rc.1"):
        return package(self.source, self.root / "output", version, revision or self.revision)

    def test_revision_languages_and_every_payload_hash_are_recorded(self):
        archive = self.build()
        with zipfile.ZipFile(archive) as zf:
            self.assertEqual(json.loads(zf.read("BUILDINFO.json"))["source_revision"], self.revision)
            for line in zf.read("SHA256SUMS.txt").decode().splitlines():
                digest, name = line.split("  ", 1)
                self.assertEqual(hashlib.sha256(zf.read(name)).hexdigest(), digest)
            self.assertIn("PRIVACY.md", zf.namelist())
            self.assertIn("LICENSE", zf.namelist())
        self.assertIn(hashlib.sha256(archive.read_bytes()).hexdigest(),
                      (archive.parent / "SHA256SUMS.txt").read_text())

    def test_mismatched_revision_is_rejected(self):
        with self.assertRaises(ValueError):
            self.build(revision="b" * 40)

    def test_stale_or_missing_language_is_rejected(self):
        (self.source / "lang/en.ini").write_text("stale")
        with self.assertRaises(ValueError):
            self.build()

    def test_wrong_architecture_is_rejected(self):
        data = bytearray((self.source / "NetLurker.exe").read_bytes())
        struct.pack_into("<H", data, 132, 0x14c)
        (self.source / "NetLurker.exe").write_bytes(data)
        with self.assertRaises(ValueError):
            self.build()

    def test_invalid_version_and_overwrite_are_rejected(self):
        for version in ("../escape", "v6.0.0", "5.0.0"):
            with self.assertRaises(ValueError):
                self.build(version=version)
        self.build()
        with self.assertRaises(FileExistsError):
            self.build()


class SmokeGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "ui-tests-exit.txt").write_text("0")
        (self.root / "smoke-steps.txt").write_text("\n".join(
            f"{name}=0" for name in ("wait_for_device", "install", "am_start", "dumpsys", "logcat", "screencap", "chmod", "gradle")))
        (self.root / "activities.txt").write_text("mResumedActivity: dev.netlurker.android.debug/MainActivity")
        (self.root / "logcat.txt").write_text("no crash fixture")
        (self.root / "screen.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    def test_valid_evidence_is_accepted(self):
        verify(self.root)

    def test_green_tests_do_not_override_a_launch_crash(self):
        (self.root / "logcat.txt").write_text("FATAL EXCEPTION: main")
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_missing_launch_evidence_is_rejected(self):
        (self.root / "smoke-steps.txt").write_text("gradle=0")
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_another_resumed_app_is_not_a_success(self):
        (self.root / "activities.txt").write_text("dev.netlurker.android\nmResumedActivity: other.package")
        with self.assertRaises(ValueError):
            verify(self.root)


if __name__ == "__main__":
    unittest.main()
