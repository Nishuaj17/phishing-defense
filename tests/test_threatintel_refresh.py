import tempfile
import unittest
from pathlib import Path

import requests

from engine.threatintel import LocalBlocklist
from engine.urlfeatures import parse_url
from scripts.refresh_threatintel import looks_healthy, refresh

GOOD_FEED = "\n".join(
    ["# some header comment"] + [f"http://bad{i}.example/payload.php" for i in range(25)]
)


class RefreshLogicTests(unittest.TestCase):
    def test_healthy_feed_detection(self):
        self.assertTrue(looks_healthy(GOOD_FEED))
        self.assertFalse(looks_healthy("# header only\n"))
        self.assertFalse(looks_healthy(""))

    def test_successful_refresh_writes_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "urlhaus.txt"
            ok, msg = refresh(str(out), fetch=lambda url: GOOD_FEED)
            self.assertTrue(ok)
            self.assertIn("25 indicators", msg)
            self.assertTrue(out.exists())
            self.assertIn("http://bad0.example/payload.php", out.read_text())

    def test_broken_download_does_not_touch_an_existing_good_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "urlhaus.txt"
            refresh(str(out), fetch=lambda url: GOOD_FEED)
            original = out.read_text()
            ok, msg = refresh(str(out), fetch=lambda url: "# empty feed today\n")
            self.assertFalse(ok)
            self.assertEqual(out.read_text(), original)  # untouched, old protection stays active

    def test_network_error_does_not_touch_an_existing_good_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "urlhaus.txt"
            refresh(str(out), fetch=lambda url: GOOD_FEED)
            original = out.read_text()

            def fails(url):
                raise requests.ConnectionError("no network")

            ok, msg = refresh(str(out), fetch=fails)
            self.assertFalse(ok)
            self.assertIn("Download failed", msg)
            self.assertEqual(out.read_text(), original)

    def test_broken_first_download_creates_no_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "urlhaus.txt"
            ok, _ = refresh(str(out), fetch=lambda url: "nothing useful")
            self.assertFalse(ok)
            self.assertFalse(out.exists())

    def test_refreshed_file_is_directly_usable_by_local_blocklist(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "urlhaus.txt"
            refresh(str(out), fetch=lambda url: GOOD_FEED)
            bl = LocalBlocklist(out)
            hit = bl.lookup(parse_url("http://bad3.example/payload.php"))
            self.assertIsNotNone(hit)
            self.assertEqual(hit.kind, "url")
            self.assertIsNone(bl.lookup(parse_url("http://totally-fine.example/")))


if __name__ == "__main__":
    unittest.main()
