"""Offline documentation checks; external accounts are not contacted."""
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
EMAIL = "mailto:user2102392109@proton.me"
TIKTOK = "https://tiktok.com/szoboszlai2113"


def anchors(text):
    result = set(re.findall(r'<a\s+id="([^"]+)"', text))
    for heading in re.findall(r"^#{1,6}\s+(.+)$", text, re.M):
        result.add(re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-"))
    return result


class DocumentationTest(unittest.TestCase):
    def test_readmes_and_landing_use_the_provided_contact_links(self):
        for name in ("README.md", "README.tr.md", "docs/landing/index.html"):
            with self.subTest(file=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn(TIKTOK, text)
                self.assertIn(EMAIL, text)
        self.assertIn(EMAIL, (ROOT / "SECURITY.md").read_text(encoding="utf-8"))

    def test_local_markdown_links_and_readme_anchors_resolve(self):
        files = list(ROOT.glob("*.md")) + list((ROOT / "docs").rglob("*.md")) + [ROOT / "android/README-android.md"]
        for source in files:
            text = re.sub(r"```.*?```", "", source.read_text(encoding="utf-8"), flags=re.S)
            for href in re.findall(r"\]\(([^)\s]+)\)", text):
                url = urlsplit(href)
                if url.scheme or url.netloc:
                    continue
                target = (source.parent / unquote(url.path)).resolve() if url.path else source
                with self.subTest(source=str(source.relative_to(ROOT)), href=href):
                    self.assertTrue(target.exists(), f"Missing link target: {target}")
                    if url.fragment and target.name in ("README.md", "README.tr.md"):
                        self.assertIn(unquote(url.fragment), anchors(target.read_text(encoding="utf-8")))

    def test_subtitles_are_ordered_and_link_to_this_repository(self):
        blocks = (ROOT / "docs/video/subtitles.srt").read_text(encoding="utf-8").strip().split("\n\n")
        end = 0
        for number, block in enumerate(blocks, 1):
            lines = block.splitlines()
            self.assertEqual(lines[0], str(number))
            times = re.fullmatch(r"(\d\d):(\d\d):(\d\d),(\d{3}) --> (\d\d):(\d\d):(\d\d),(\d{3})", lines[1])
            self.assertIsNotNone(times)
            values = list(map(int, times.groups()))
            start = ((values[0] * 60 + values[1]) * 60 + values[2]) * 1000 + values[3]
            finish = ((values[4] * 60 + values[5]) * 60 + values[6]) * 1000 + values[7]
            self.assertGreaterEqual(start, end)
            self.assertGreater(finish, start)
            end = finish
        self.assertEqual(end, 30000)
        self.assertIn("github.com/thesyntax1/NetLurker", blocks[-1])
        self.assertTrue(any("DEMO" in block for block in blocks))


if __name__ == "__main__":
    unittest.main()
