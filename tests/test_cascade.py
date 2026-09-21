import json
import unittest

from engine.cascade import Analyzer, fuse, label_action
from engine.fusion import LogitFusion
from engine.fetcher import FetchResult
from engine.types import Evidence
from engine.urlmodel import UrlPrediction
from tests.test_page import BLOG, PHISH

URL = "http://paypal-secure-login.verify-account.xyz/signin"


class StubModel:
    version = "stub-v0"

    def __init__(self, score):
        self.score = score

    def predict(self, url):
        return UrlPrediction(self.score, [Evidence("url", "Stub signal", "detail", 1.0)], self.version)


class Fetcher:
    def __init__(self, html=None, error=""):
        self.calls = []
        self.html, self.error = html, error

    def __call__(self, url):
        self.calls.append(url)
        if self.error:
            return FetchResult(ok=False, error=self.error, ms=5)
        return FetchResult(ok=True, final_url=url, status=200, html=self.html, ms=120)


class CascadeTests(unittest.TestCase):
    def make(self, score, fetcher):
        return Analyzer(StubModel(score), fetch=fetcher, t_low=0.06, t_high=0.93)

    def test_clearly_safe_address_never_opens_the_page(self):
        f = Fetcher(BLOG)
        a = self.make(0.01, f).analyze("https://example.org/")
        self.assertEqual(f.calls, [])
        self.assertEqual((a.recommended_action, a.label, a.stopped_at), ("allow", "safe", "url"))
        self.assertEqual((a.enforcement, a.verified), ("advisory", True))
        self.assertEqual([s["outcome"] for s in a.stages], ["stop", "skipped"])

    def test_clearly_bad_address_blocks_without_touching_the_server(self):
        f = Fetcher(PHISH)
        a = self.make(0.99, f).analyze(URL)
        self.assertEqual(f.calls, [])
        self.assertEqual((a.recommended_action, a.stopped_at), ("block", "url"))

    def test_uncertain_address_escalates_to_the_page(self):
        f = Fetcher(PHISH)
        a = self.make(0.5, f).analyze(URL)
        self.assertEqual(len(f.calls), 1)
        self.assertEqual((a.recommended_action, a.stopped_at), ("block", "page"))
        self.assertGreaterEqual(a.risk, 90)
        self.assertEqual([s["name"] for s in a.stages], ["url", "page"])
        self.assertEqual({e["stage"] for e in a.evidence}, {"url", "page"})

    def test_uncertain_address_but_clean_page_is_cleared(self):
        a = self.make(0.3, Fetcher(BLOG)).analyze("https://myblog.example.org/post")
        self.assertEqual(a.recommended_action, "allow")
        self.assertEqual(a.stopped_at, "page")

    def test_unreachable_page_falls_back_to_the_address_score(self):
        a = self.make(0.5, Fetcher(error="The domain does not resolve.")).analyze(URL)
        self.assertEqual(a.stages[1]["outcome"], "unavailable")
        self.assertEqual(a.risk, 50)
        self.assertEqual(a.recommended_action, "warn")
        self.assertFalse(a.verified)
        self.assertEqual(a.modalities["webpage"]["status"], "unavailable")
        self.assertIn("address alone", a.stages[1]["note"])

    def test_unreachable_page_is_never_reported_as_safe(self):
        # address score is mildly uncertain, page cannot be opened, risk would round to "safe"
        a = self.make(0.10, Fetcher(error="The domain does not resolve.")).analyze("http://example.org/")
        self.assertEqual((a.label, a.recommended_action, a.verified), ("unverified", "warn", False))
        self.assertIn("unchecked", " ".join(a.guidance["do_now"]))

    def test_result_separates_probability_risk_label_and_enforcement(self):
        a = self.make(0.5, Fetcher(PHISH)).analyze(URL)
        self.assertTrue(0.0 <= a.probability <= 1.0)
        self.assertEqual(a.risk, round(a.probability * 100))
        self.assertEqual(a.enforcement, "advisory")
        self.assertFalse(a.calibrated)  # default fusion is a hand-set prior, not a fitted probability
        self.assertEqual(a.modalities["visual"]["status"], "not_implemented")
        self.assertEqual(a.modalities["threat_intel"]["status"], "not_configured")

    def test_full_mode_always_inspects_the_page(self):
        f = Fetcher(BLOG)
        a = self.make(0.01, f).analyze("https://example.org/", mode="full")
        self.assertEqual(len(f.calls), 1)
        self.assertEqual(a.stages[1]["outcome"], "done")
        self.assertEqual(a.modalities["webpage"]["status"], "done")

    def test_supplied_html_skips_fetching(self):
        f = Fetcher(BLOG)
        a = self.make(0.5, f).analyze(URL, html=PHISH)
        self.assertEqual(f.calls, [])
        self.assertEqual(a.recommended_action, "block")

    def test_rejects_bad_input(self):
        an = self.make(0.5, Fetcher(BLOG))
        for bad in ("", "   ", "http://exa mple.com", "https://a.com/\x00", "a" * 3000, "https:///x"):
            with self.subTest(bad=bad[:20]), self.assertRaises(ValueError):
                an.analyze(bad)

    def test_result_is_json_serialisable_and_bounded(self):
        a = self.make(0.5, Fetcher(PHISH)).analyze(URL)
        d = json.loads(json.dumps(a.to_dict()))
        self.assertLessEqual(len(d["evidence"]), 8)
        self.assertTrue(all(0 <= e["impact"] <= 1 for e in d["evidence"]))
        self.assertEqual(d["parts"]["domain"], "verify-account.xyz")
        self.assertEqual(d["parts"]["subdomain"], "paypal-secure-login")


class FusionTests(unittest.TestCase):
    def test_fusion_is_monotonic_and_bounded(self):
        self.assertLess(fuse(0.2, 0.2), fuse(0.2, 0.9))
        self.assertLess(fuse(0.2, 0.9), fuse(0.9, 0.9))
        for a in (0.0, 0.5, 1.0):
            for b in (0.0, 0.5, 1.0):
                self.assertTrue(0.0 < fuse(a, b) < 1.0)

    def test_page_evidence_can_override_a_suspicious_address(self):
        self.assertLess(fuse(0.9, 0.05), 0.5)

    def test_quiet_modalities_do_not_drown_out_a_loud_one(self):
        # two "nothing suspicious" scores carry a built-in negative prior; fusion must not treat that as evidence of safety
        loud = LogitFusion().predict({"url": 0.04, "page": 0.99})
        self.assertGreater(loud, 0.75)

    def test_label_thresholds(self):
        self.assertEqual(label_action(10), ("safe", "allow"))
        self.assertEqual(label_action(30), ("suspicious", "warn"))
        self.assertEqual(label_action(65), ("phishing", "block"))


if __name__ == "__main__":
    unittest.main()
