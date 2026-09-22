import unittest
 
from scripts.inspect_samples import describe
 
 
class InspectTests(unittest.TestCase):
    def test_describes_a_phishing_row(self):
        r = {"url": "http://paypal-secure.example.top/x", "final_url": "http://paypal-secure.example.top/x", "status": 200,
             "label": 1, "html": "<html><title>PayPal Login</title><body>Sign in<form action='https://c.evil.ru/p'>"
                                 "<input type=password></form></body></html>"}
        d = describe(r)
        self.assertEqual(d["title"], "PayPal Login")
        self.assertTrue(d["login_form"] and d["form_sends_elsewhere"])
        self.assertFalse(d["moved_to_other_domain"])
 
    def test_flags_a_row_that_redirected_to_another_domain(self):
        r = {"url": "http://phish.example.top/x", "final_url": "https://www.google.com/", "status": 200, "label": 1,
             "html": "<html><title>Google</title><body>hello</body></html>"}
        self.assertTrue(describe(r)["moved_to_other_domain"])
 
 
if __name__ == "__main__":
    unittest.main()
 
