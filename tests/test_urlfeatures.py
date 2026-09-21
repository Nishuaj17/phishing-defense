import unittest

from engine.urlfeatures import FEATURE_NAMES, extract_features, feature_vector, parse_url, split_host
from engine.urlmodel import UrlModel


class SplitHostTests(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(split_host("www.google.com"), ("www", "google.com", "com"))
        self.assertEqual(split_host("shop.myshop.co.in"), ("shop", "myshop.co.in", "co.in"))
        self.assertEqual(split_host("a.b.example.com")[1], "example.com")

    def test_free_hosting_is_its_own_registered_domain(self):
        self.assertEqual(split_host("evil.github.io")[1], "evil.github.io")

    def test_ip_host(self):
        self.assertEqual(split_host("185.12.44.9"), ("", "185.12.44.9", ""))


class ParseTests(unittest.TestCase):
    def test_adds_scheme(self):
        self.assertEqual(parse_url("example.com/a").scheme, "https")

    def test_userinfo_detected_and_real_host_used(self):
        p = parse_url("http://paypal.com@evil.example.net/x")
        self.assertTrue(p.has_userinfo)
        self.assertEqual(p.host, "evil.example.net")

    def test_rejects_hostless(self):
        with self.assertRaises(ValueError):
            parse_url("https:///path")


class FeatureTests(unittest.TestCase):
    def test_feature_names_match(self):
        self.assertEqual(set(extract_features("https://a.com").keys()), set(FEATURE_NAMES))
        self.assertEqual(len(feature_vector("https://a.com")), len(FEATURE_NAMES))

    def test_brand_mismatch(self):
        f = extract_features("http://paypal-secure-login.verify-account.xyz/signin")
        self.assertEqual(f["brand_in_subdomain_mismatch"], 1.0)
        self.assertEqual(f["suspicious_tld"], 1.0)
        self.assertEqual(f["is_https"], 0.0)
        self.assertEqual(extract_features("https://paypa1-login.com/")["brand_in_domain_mismatch"], 1.0)

    def test_no_false_brand_flags_on_legit_or_lookalike_words(self):
        for url in ("https://www.paypal.com/signin", "https://login.microsoftonline.com/x",
                    "https://pineapple.com/shop", "https://www.amazon.co.uk/gp/css"):
            f = extract_features(url)
            self.assertEqual(f["brand_in_domain_mismatch"] + f["brand_in_subdomain_mismatch"], 0.0, url)

    def test_ip_host(self):
        self.assertEqual(extract_features("http://185.12.44.9/login")["has_ip_host"], 1.0)


class HeuristicScoreTests(unittest.TestCase):
    def setUp(self):
        self.m = UrlModel()

    def test_ordering(self):
        good = self.m.predict("https://github.com/openai/openai-python").score
        bad = self.m.predict("http://paypal-secure-login.verify-account.xyz/signin").score
        self.assertLess(good, 0.06)
        self.assertGreater(bad, 0.93)

    def test_evidence_explains_the_score(self):
        ev = self.m.predict("http://paypal-secure-login.verify-account.xyz/signin").evidence
        signals = {e.signal for e in ev}
        self.assertIn("Brand name used as a subdomain", signals)
        self.assertIn("Not encrypted", signals)
        self.assertTrue(all(e.weight > 0 for e in ev))


if __name__ == "__main__":
    unittest.main()
