import json
import tempfile
import unittest
from pathlib import Path
 
from scripts.collect_dataset import refuse_overwrite
from scripts.merge_dataset import summarise
 
 
class OverwriteGuardTests(unittest.TestCase):
    def test_existing_output_is_refused_before_anything_is_fetched(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "paired.jsonl"
            refuse_overwrite(str(out), str(Path(d) / "u.csv"))  # nothing exists yet: fine
            out.write_text("precious data")
            with self.assertRaises(SystemExit) as ctx:
                refuse_overwrite(str(out), str(Path(d) / "u.csv"))
            self.assertIn("already exists", str(ctx.exception))
            self.assertEqual(out.read_text(), "precious data")
            refuse_overwrite(str(out), overwrite=True)  # explicit opt-in
 
 
class KitCountTests(unittest.TestCase):
    def test_identical_pages_on_different_domains_count_as_one_kit(self):
        kit = "<html><title>iCloud</title></html>"
        rows = [{"url": f"http://a{i}.example/x", "label": 1, "ts": i, "html": kit, "final_url": f"http://a{i}.example/x"}
                for i in range(3)]
        rows.append({"url": "http://z.example/", "label": 1, "ts": 9, "html": "<html>other</html>", "final_url": "http://z.example/"})
        s = summarise(rows)
        self.assertEqual((s["phishing_with_html"], s["phishing_distinct_html"]), (4, 2))
 
 
if __name__ == "__main__":
    unittest.main()
 
