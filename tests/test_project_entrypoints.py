"""Offline checks for the public landing page; not a browser/visual audit."""
from html.parser import HTMLParser
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids = []
        self.links = []
        self.images = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "a":
            self.links.append(attrs.get("href", ""))
        if tag == "img":
            self.images.append(attrs.get("src", ""))


class EntryPointTest(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / "docs/landing/index.html").read_text(encoding="utf-8")
        self.page = Page(self.text)

    def test_navigation_targets_and_local_assets_exist(self):
        self.assertEqual(len(self.page.ids), len(set(self.page.ids)))
        for link in self.page.links:
            if link.startswith("#"):
                self.assertIn(link[1:], self.page.ids)
        for asset in self.page.images:
            if "://" not in asset:
                self.assertTrue((ROOT / "docs/landing" / asset).is_file())

    def test_downloads_do_not_claim_unverified_compatibility_or_production_android(self):
        self.assertNotIn("Windows 7+", self.text)
        self.assertIn("Production APK publication is off by default", self.text)
        self.assertIn("SHA256SUMS.txt", self.text)
        self.assertIn("including its <code>lang/</code> folder", self.text)

    def test_keyboard_entry_and_language_guidance_are_present(self):
        self.assertIn('<main id="content">', self.text)
        self.assertIn('href="#content">Skip to content', self.text)
        self.assertIn(":focus-visible", self.text)
        self.assertIn("language picker is at the top", self.text)


if __name__ == "__main__":
    unittest.main()
