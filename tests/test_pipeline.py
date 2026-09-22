import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
 
from app.ratelimit import TokenBucket
from app.store import Store
from engine.cascade import Analyzer
from engine.urlmodel import UrlModel
from experiments.evaluate import evaluate, select_test_rows
from scripts.collect_dataset import benign_urls, collect, load_seen, valid_urls
from scripts.merge_dataset import merge, summarise
from scripts.make_synthetic_smoke_data import make_rows
 
ROOT = Path(__file__).resolve().parent.parent
 
 
class TrainEvaluateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        cls.rows = make_rows(900, seed=3)  # SYNTHETIC: exercises the plumbing, proves nothing about detection
        with open(tmp / "urls.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["url", "label", "ts"])
            w.writerows((r["url"], r["label"], r["ts"]) for r in cls.rows)
        cls.model_path = tmp / "m.joblib"
        proc = subprocess.run(
            [sys.executable, "-m", "ml.train_url_model", "--csv", str(tmp / "urls.csv"),
             "--out", str(cls.model_path), "--version", "url-test"],
            cwd=ROOT, capture_output=True, text=True)
        cls.train = proc
 
    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
 
    def test_training_cli_succeeds_and_saves_bundle(self):
        self.assertEqual(self.train.returncode, 0, self.train.stderr)
        self.assertTrue(self.model_path.exists())
        self.assertTrue(self.model_path.with_suffix(".metrics.json").exists())
        self.assertIn("time split", self.train.stdout)
 
    def test_trained_model_predicts_and_explains(self):
        m = UrlModel(self.model_path)
        self.assertEqual((m.kind, m.version), ("ml", "url-test"))
        self.assertIsNotNone(m.split_ts)
        bad = m.predict("http://paypal-secure-login.verify-account.xyz/signin")
        good = m.predict("https://www.maple.org/river")
        self.assertGreater(bad.score, 0.5)
        self.assertLess(good.score, 0.5)
        self.assertTrue(bad.evidence)
        self.assertTrue(all(0 <= e.weight for e in bad.evidence))
 
    def test_trained_model_works_inside_the_cascade(self):
        a = Analyzer(UrlModel(self.model_path)).analyze(
            "http://paypal-secure-login.verify-account.xyz/signin", html=self.rows[0]["html"])
        self.assertIn(a.recommended_action, ("allow", "warn", "block"))
        self.assertEqual(a.versions["url_model"], "url-test")
 
    def test_evaluation_uses_only_heldout_rows_and_reports_all_methods(self):
        m = UrlModel(self.model_path)
        test_rows, note = select_test_rows(self.rows, m, 0.2)
        self.assertTrue(all(r["ts"] >= m.split_ts for r in test_rows))
        self.assertIn("training boundary", note)
        res = evaluate(test_rows, m, 0.06, 0.93, sweep=True)
        for key in ("url_only", "page_only", "fused_default", "cascade"):
            self.assertIn("roc_auc", res[key])
        self.assertEqual(len(res["sweep"]), 20)
        self.assertTrue(0.0 <= res["cascade"]["escalation_rate"] <= 1.0)
 
    def test_heuristic_baseline_evaluates_without_a_model_file(self):
        m = UrlModel()
        rows, note = select_test_rows(self.rows, m, 0.2)
        self.assertIn("newest 20%", note)
        res = evaluate(rows, m, 0.06, 0.93)
        self.assertGreater(res["url_only"]["roc_auc"], 0.5)
 
 
class CollectorTests(unittest.TestCase):
    def test_seen_urls_are_loaded_and_missing_file_is_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(load_seen(str(Path(d) / "none.txt")), set())
            (Path(d) / "seen.txt").write_text("http://a.example/x\nhttp://b.example/y\n")
            self.assertEqual(load_seen(str(Path(d) / "seen.txt")), {"http://a.example/x", "http://b.example/y"})
 
    def test_merge_sorts_by_time_and_drops_repeats(self):
        def row(url, label, ts, html="<html>x</html>"):
            return json.dumps({"url": url, "label": label, "ts": ts, "html": html, "final_url": url})
 
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a.jsonl", Path(d) / "b.jsonl"
            a.write_text(row("http://p.example/", 1, 200) + "\n" + row("http://q.example/", 0, 300, "") + "\n")
            b.write_text(row("http://p.example/", 1, 100) + "\n" + row("http://r.example/login", 0, 400,
                         "<form><input type=password></form>") + "\n")
            rows = merge([str(a), str(b)])
        self.assertEqual([r["url"] for r in rows], ["http://p.example/", "http://q.example/", "http://r.example/login"])
        self.assertEqual(rows[0]["ts"], 100)  # earliest sighting kept
        s = summarise(rows)
        self.assertEqual((s["rows"], s["phishing"], s["benign"], s["with_html"]), (3, 1, 2, 2))
        self.assertEqual(s["benign_pages_with_login_form"], 1)
 
    def test_feed_junk_is_not_treated_as_urls(self):
        junk = ["<html>", "<head><title>302 Found</title></head>", "", "not a url", "ftp://x.example/a",
                "http://a.example/x", "HTTPS://B.example/y", "http://a.example/x"]
        self.assertEqual(valid_urls(junk), ["http://a.example/x", "HTTPS://B.example/y"])
 
    def test_benign_urls_cover_home_and_login(self):
        urls = benign_urls(["1,example.com", "2,example.org"], ["/", "/login"])
        self.assertEqual(urls, ["https://example.com/", "https://example.com/login",
                                "https://example.org/", "https://example.org/login"])
 
    def test_collect_records_failures_without_html(self):
        from engine.fetcher import FetchResult
 
        def fake(url):
            if "bad" in url:
                return FetchResult(ok=False, error="The domain does not resolve.", ms=3)
            return FetchResult(ok=True, final_url=url, status=200, html="<html>x</html>", ms=10)
 
        rows = collect([("http://good.example/", 0), ("http://bad.example/", 1)], fetch=fake, workers=2)
        by_url = {r["url"]: r for r in rows}
        self.assertTrue(by_url["http://good.example/"]["fetch_ok"])
        self.assertEqual(by_url["http://bad.example/"]["html"], "")
 
    def test_error_pages_are_not_stored_as_samples(self):
        from engine.fetcher import FetchResult
 
        def fake(url):
            code = 404 if "missing" in url else 200
            return FetchResult(ok=True, final_url=url, status=code, html="<html>Not found</html>" if code == 404 else "<html>ok</html>", ms=5)
 
        rows = {r["url"]: r for r in collect([("http://a.example/", 0), ("http://a.example/missing", 0)], fetch=fake, workers=2)}
        self.assertTrue(rows["http://a.example/"]["fetch_ok"])
        bad = rows["http://a.example/missing"]
        self.assertEqual((bad["fetch_ok"], bad["html"], bad["error"]), (False, "", "HTTP 404"))
 
 
class AppPartsTests(unittest.TestCase):
    def test_rate_limiter(self):
        now = [0.0]
        tb = TokenBucket(per_minute=60, burst=3, clock=lambda: now[0])
        self.assertEqual([tb.allow("a")[0] for _ in range(3)], [True, True, True])
        ok, retry = tb.allow("a")
        self.assertFalse(ok)
        self.assertEqual(retry, 1)
        self.assertTrue(tb.allow("b")[0])  # other clients unaffected
        now[0] = 1.0
        self.assertTrue(tb.allow("a")[0])
 
    def test_store_saves_and_summarises(self):
        a = Analyzer().analyze("http://paypal-secure-login.verify-account.xyz/signin").to_dict()
        s = Store(":memory:")
        s.save(a)
        self.addCleanup(s.close)
        self.assertEqual(s.recent(5)[0]["url"], a["url"])
        st = s.stats()
        self.assertEqual((st["total"], st["by_action"]), (1, {"block": 1}))
        self.assertEqual(st["decided_by_address_share"], 1.0)
 
    def test_store_can_keep_hostnames_only(self):
        s = Store(":memory:", store_urls=False)
        self.addCleanup(s.close)
        from engine.fetcher import FetchResult
        offline = Analyzer(fetch=lambda u: FetchResult(ok=False, error="offline", ms=0))  # no real network in tests
        s.save(offline.analyze("http://example.com/reset?token=SECRET").to_dict())
        self.assertEqual(s.recent(1)[0]["url"], "example.com")
 
 
if __name__ == "__main__":
    unittest.main()
 
