import json
import tempfile
import unittest
from pathlib import Path

from app.ratelimit import TokenBucket
from app.store import Store
from engine.cascade import Analyzer
from engine.fetcher import FetchResult
from engine.fusion import LogitFusion
from engine.response import guidance, indicators
from engine.textfeatures import analyze_text, extract_urls
from engine.threatintel import LocalBlocklist, ThreatIntel, TIHit
from engine.urlfeatures import parse_url
from engine.urlmodel import UrlModel
from experiments.evaluate import evaluate, fit_fusion_on, select_heldout_rows, split_val_test
from scripts.export_feedback import disagrees
from scripts.make_synthetic_smoke_data import make_rows
from tests.test_page import BLOG, PHISH

SCAM = ("Dear customer, your SBI account has been suspended. Verify your KYC immediately: "
        "http://sbi-kyc-update.github.io/verify")


def offline(url):
    return FetchResult(ok=False, error="offline", ms=1)


class Counting:
    def __init__(self, html=None):
        self.calls, self.html = [], html

    def __call__(self, url):
        self.calls.append(url)
        if self.html is None:
            return FetchResult(ok=False, error="offline", ms=1)
        return FetchResult(ok=True, final_url=url, status=200, html=self.html, ms=50)


class TextTests(unittest.TestCase):
    def test_scam_wording_scores_high_and_normal_chat_low(self):
        self.assertGreater(analyze_text(SCAM).score, 0.4)
        self.assertLess(analyze_text("Hi! Are we still on for lunch tomorrow?").score, 0.1)

    def test_legitimate_otp_notice_is_not_flagged(self):
        self.assertLess(analyze_text("Your OTP is 482913. Do not share it with anyone.").score, 0.2)

    def test_sender_name_versus_address(self):
        r = analyze_text("Please review your statement.", sender="PayPal Support <help@gmail.com>")
        self.assertIn("Sender name doesn't match sender address", {e.signal for e in r.evidence})
        self.assertEqual(r.sender_domain, "gmail.com")

    def test_lookalike_sender_domain(self):
        r = analyze_text("Your invoice is ready.", sender="billing@paypal-secure.top")
        self.assertIn("Look-alike sender domain", {e.signal for e in r.evidence})

    def test_real_sender_domain_is_not_flagged(self):
        r = analyze_text("Your receipt.", sender="PayPal <service@paypal.com>")
        self.assertEqual([e for e in r.evidence if "Sender" in e.signal or "sender" in e.signal], [])

    def test_brands_are_claimed_by_the_prose_not_by_the_urls_inside_it(self):
        r = analyze_text(SCAM)
        self.assertEqual(r.claimed_brands, ["sbi"])

    def test_extract_urls(self):
        urls, total = extract_urls("see www.example.com/a, and http://x.io/b). also bit.ly/zz http://x.io/b", 5)
        self.assertEqual(urls, ["www.example.com/a", "http://x.io/b", "bit.ly/zz"])
        self.assertEqual(total, 3)
        self.assertEqual(len(extract_urls("http://a.io http://b.io http://c.io http://d.io", 2)[0]), 2)
        self.assertEqual(extract_urls("no links here")[0], [])


class MessageTests(unittest.TestCase):
    def make(self, fetch=offline, **kw):
        return Analyzer(fetch=fetch, **kw)

    def test_scam_message_is_blocked_with_cross_modal_evidence(self):
        a = self.make().analyze_message(SCAM, "SBI Support <alerts@gmail.com>", "Account suspended")
        self.assertEqual((a.kind, a.recommended_action), ("message", "block"))
        signals = {e["signal"] for e in a.evidence}
        self.assertIn("Message and links disagree", signals)
        self.assertIn("Sender name doesn't match sender address", signals)
        self.assertEqual(len(a.links), 1)
        self.assertEqual(a.stages[0]["name"], "text")
        self.assertEqual(a.modalities["text"]["status"], "done")
        self.assertEqual(a.modalities["visual"]["status"], "not_implemented")
        self.assertEqual(a.versions["text_model"], "text-heuristic-v1")
        self.assertIn("sbi-kyc-update.github.io", [i["value"] for i in a.indicators])

    def test_innocent_sentence_cannot_dilute_a_phishing_link(self):
        a = self.make().analyze_message("Check this out https://paypal-secure-login.verify-account.xyz/signin")
        self.assertEqual(a.recommended_action, "block")

    def test_benign_message_with_benign_link_is_allowed(self):
        a = self.make(Counting(BLOG)).analyze_message("Hi! Here's the menu https://github.com/openai")
        self.assertEqual((a.label, a.recommended_action), ("safe", "allow"))

    def test_scam_wording_without_a_link_still_warns(self):
        a = self.make().analyze_message("Your account has been suspended. Verify your password immediately or face legal action.")
        self.assertIn(a.recommended_action, ("warn", "block"))
        self.assertEqual(a.links, [])
        self.assertEqual(a.stopped_at, "text")

    def test_passing_brand_mention_is_not_a_mismatch(self):
        a = self.make().analyze_message("I bought it on Amazon, read the review https://example.org/post")
        self.assertNotIn("Message and links disagree", {e["signal"] for e in a.evidence})

    def test_only_the_first_links_are_opened_and_the_rest_are_reported(self):
        f = Counting()
        text = " ".join(f"http://site{i}.example/x" for i in range(6))
        a = self.make(f, max_links=3).analyze_message(text)
        self.assertLessEqual(len(f.calls), 3)
        self.assertEqual(len(a.links), 3)
        self.assertIn("3 more link(s)", a.stages[0]["note"])

    def test_rejects_bad_input(self):
        an = self.make()
        for bad in ("", "   ", "x" * 5001):
            with self.subTest(n=len(bad)), self.assertRaises(ValueError):
                an.analyze_message(bad)
        with self.assertRaises(ValueError):
            an.analyze_message("hello there", sender="a" * 400)

    def test_json_serialisable(self):
        a = self.make().analyze_message(SCAM)
        json.dumps(a.to_dict())


class ThreatIntelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = Path(self.tmp.name) / "bad.txt"
        path.write_text("# comment\nevil.example\n\nhttp://other.example/exact/path\n")
        self.bl = LocalBlocklist(path)

    def test_matches_domain_subdomain_and_exact_url_only(self):
        self.assertEqual(self.bl.lookup(parse_url("http://evil.example/x")).kind, "domain")
        self.assertEqual(self.bl.lookup(parse_url("http://login.evil.example/x")).indicator, "evil.example")
        self.assertEqual(self.bl.lookup(parse_url("http://other.example/exact/path")).kind, "url")
        self.assertIsNone(self.bl.lookup(parse_url("http://notevil.example/x")))
        self.assertIsNone(self.bl.lookup(parse_url("http://other.example/different")))

    def test_hit_is_a_policy_floor_and_skips_the_page(self):
        f = Counting(BLOG)
        an = Analyzer(fetch=f, ti=ThreatIntel([self.bl]))
        a = an.analyze("http://evil.example/harmless-looking")
        self.assertEqual(f.calls, [])
        self.assertGreaterEqual(a.risk, 95)
        self.assertEqual((a.stopped_at, a.recommended_action), ("intel", "block"))
        self.assertEqual(a.modalities["threat_intel"]["status"], "hit")
        self.assertIn("Listed on a threat list", {e["signal"] for e in a.evidence})
        # the model input was untouched: the address score is the plain model score
        self.assertLess(a.stages[0]["score"], 0.2)

    def test_full_mode_still_does_not_open_a_listed_page(self):
        f = Counting(BLOG)
        Analyzer(fetch=f, ti=ThreatIntel([self.bl])).analyze("http://evil.example/x", mode="full")
        self.assertEqual(f.calls, [])

    def test_clear_when_configured_and_no_hit(self):
        a = Analyzer(fetch=offline, ti=ThreatIntel([self.bl])).analyze("https://github.com/openai")
        self.assertEqual(a.modalities["threat_intel"]["status"], "clear")

    def test_broken_provider_is_ignored(self):
        class Broken:
            def lookup(self, p):
                raise RuntimeError("api down")

        class Fixed:
            def lookup(self, p):
                return TIHit("fixed", p.host, "domain")

        hits = ThreatIntel([Broken(), Fixed()]).check(parse_url("http://a.example"))
        self.assertEqual([h.source for h in hits], ["fixed"])

    def test_evaluation_module_never_uses_threat_intel(self):
        import experiments.evaluate as ev

        self.assertNotIn("threatintel", Path(ev.__file__).read_text().replace("engine/threatintel.py", ""))


class ResponseTests(unittest.TestCase):
    def test_guidance_by_verdict(self):
        self.assertEqual(guidance("safe", "allow")["if_you_interacted"], [])
        blocked = guidance("phishing", "block")
        self.assertTrue(blocked["if_you_interacted"] and blocked["report"])
        self.assertTrue(any("multi-factor" in s.lower() for s in blocked["if_you_interacted"]))
        self.assertIn("unchecked", " ".join(guidance("unverified", "warn")["do_now"]))

    def test_guidance_never_claims_automation(self):
        text = json.dumps(guidance("phishing", "block")).lower()
        for claim in ("we have reset", "we reset", "we blocked your", "automatically"):
            self.assertNotIn(claim, text)

    def test_indicators_skip_empty_values_and_keep_order(self):
        self.assertEqual(indicators(None, "", "", ""), [])
        iocs = indicators("http://a.example/x", "a.example", "collector.ru", "b.example")
        self.assertEqual([i["type"] for i in iocs], ["url", "domain", "form_action_domain", "sender_domain"])
        self.assertEqual(len(indicators("http://a.example/x", "a.example", "", "b.example")), 3)


class StoreLifecycleTests(unittest.TestCase):
    def analysis(self, url, html=None):
        an = Analyzer(fetch=Counting(html))
        return an.analyze(url).to_dict()

    def test_block_opens_an_incident_warn_does_not(self):
        s = Store(":memory:")
        self.addCleanup(s.close)
        s.save(self.analysis("http://paypal-secure-login.verify-account.xyz/signin"))
        s.save(self.analysis("http://example-portal.xyz/account"))  # warn: uncertain and unreachable
        inc = s.incidents()
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["status"], "open")
        self.assertIn("verify-account.xyz", [i["value"] for i in inc[0]["indicators"]])
        self.assertTrue(inc[0]["evidence"])
        self.assertEqual(s.stats()["incidents"], 1)

    def test_hostname_only_mode_drops_url_indicators(self):
        s = Store(":memory:", store_urls=False)
        self.addCleanup(s.close)
        s.save(self.analysis("http://paypal-secure-login.verify-account.xyz/signin?token=SECRET"))
        inc = s.incidents()
        self.assertEqual(len(inc), 1)
        self.assertNotIn("SECRET", json.dumps(inc))
        self.assertEqual([i for i in inc[0]["indicators"] if i["type"] == "url"], [])
        self.assertIn("verify-account.xyz", [i["value"] for i in inc[0]["indicators"]])

    def test_feedback_rules(self):
        s = Store(":memory:")
        self.addCleanup(s.close)
        a = self.analysis("http://paypal-secure-login.verify-account.xyz/signin")
        s.save(a)
        self.assertEqual(s.add_feedback("does-not-exist", "phishing"), "unknown")
        self.assertEqual([s.add_feedback(a["id"], "phishing") for _ in range(4)], ["ok", "ok", "ok", "limit"])
        rows = s.feedback_export()
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["analysis_id"], a["id"])

    def test_message_text_is_never_stored(self):
        s = Store(":memory:")
        self.addCleanup(s.close)
        a = Analyzer(fetch=offline).analyze_message(SCAM, "SBI Support <alerts@gmail.com>").to_dict()
        s.save(a)
        self.assertEqual(s.recent(1)[0]["url"], "(message)")
        self.assertNotIn("KYC", json.dumps(s.recent(1)))

    def test_disagreement_filter(self):
        self.assertTrue(disagrees({"recommended_action": "block", "user_verdict": "legitimate"}))
        self.assertTrue(disagrees({"recommended_action": "allow", "user_verdict": "phishing"}))
        self.assertFalse(disagrees({"recommended_action": "warn", "user_verdict": "phishing"}))


class RateLimitCostTests(unittest.TestCase):
    def test_expensive_requests_drain_more(self):
        now = [0.0]
        tb = TokenBucket(per_minute=60, burst=4, clock=lambda: now[0])
        self.assertTrue(tb.allow("a", cost=3)[0])
        ok, retry = tb.allow("a", cost=3)
        self.assertFalse(ok)
        self.assertGreaterEqual(retry, 1)
        self.assertTrue(tb.allow("a", cost=1)[0])  # one token was left
        self.assertTrue(TokenBucket(60, 2).allow("b", cost=5)[0])  # cost is capped at the bucket size


class FusionTests(unittest.TestCase):
    def test_missing_modality_is_neutral(self):
        f = LogitFusion()
        self.assertAlmostEqual(f.predict({"url": 0.7, "page": None}), f.predict({"url": 0.7}))

    def test_fit_save_load_roundtrip(self):
        rows = [{"url": 0.1, "page": 0.1}] * 30 + [{"url": 0.2, "page": 0.9}] * 30 + [{"url": 0.9, "page": 0.9}] * 30
        y = [0] * 30 + [1] * 30 + [1] * 30
        fit = LogitFusion.fit(rows, y)
        self.assertTrue(fit.calibrated and fit.weights["page"] > 0)
        self.assertLess(fit.predict({"url": 0.1, "page": 0.1}), 0.5)
        self.assertGreater(fit.predict({"url": 0.5, "page": 0.9}), 0.5)
        with tempfile.TemporaryDirectory() as d:
            fit.save(Path(d) / "f.json")
            back = LogitFusion.load(Path(d) / "f.json")
        self.assertEqual(back.weights, fit.weights)
        self.assertAlmostEqual(back.predict({"url": 0.3, "page": 0.6}), fit.predict({"url": 0.3, "page": 0.6}))

    def test_fusion_fitted_for_another_url_model_is_rejected(self):
        wrong = LogitFusion({"url": 1.0, "page": 1.0}, 0.0, "fit", calibrated=True, priors={}, meta={"url_model": "url-gbm-v9"})
        with self.assertRaises(ValueError):
            Analyzer(url_model=UrlModel(), fusion=wrong)
        ok = LogitFusion({"url": 1.0, "page": 1.0}, 0.0, "fit", calibrated=True, priors={}, meta={"url_model": "heuristic-v1"})
        Analyzer(url_model=UrlModel(), fusion=ok)

    def test_analyzer_marks_output_calibrated_only_with_a_fitted_fusion(self):
        fitted = LogitFusion({"url": 1.0, "page": 1.0}, -1.0, "fit", calibrated=True, priors={})
        # default (priors=0) weights: url is uncertain, so the page is opened and fused
        a = Analyzer(url_model=UrlModel(), fetch=Counting(PHISH), fusion=fitted).analyze(
            "http://example-portal.xyz/account")
        self.assertTrue(a.calibrated)
        self.assertEqual(a.versions["fusion"], "fit")


class LearnedFusionExperimentTests(unittest.TestCase):
    def test_validation_and_test_halves_are_time_ordered_and_disjoint(self):
        rows = make_rows(600, seed=5)  # SYNTHETIC: plumbing only
        held, _ = select_heldout_rows(rows, UrlModel(), 0.4)
        val, test = split_val_test(held)
        self.assertTrue(val and test)
        self.assertLessEqual(max(r["ts"] for r in val), min(r["ts"] for r in test))
        self.assertEqual(len(val) + len(test), len(held))

    def test_fit_then_evaluate_on_the_untouched_half(self):
        rows = make_rows(900, seed=6)
        m = UrlModel()
        held, _ = select_heldout_rows(rows, m, 0.5)
        val, test = split_val_test(held)
        fusion = fit_fusion_on(val, m)
        self.assertTrue(fusion.calibrated)
        self.assertEqual(fusion.meta["n_validation"], len(val))
        res = evaluate(test, m, 0.06, 0.93, sweep=False, fusion=fusion)
        self.assertEqual(res["n_test"], len(test))
        for key in ("url_only", "page_only", "fused_default", "fused_learned", "cascade"):
            self.assertIn("brier", res[key])
        self.assertIn("ece", res["calibration"]["cascade"])
        self.assertEqual(res["fusion_used"], "logit-fit-v1")
        json.dumps(res)


if __name__ == "__main__":
    unittest.main()
