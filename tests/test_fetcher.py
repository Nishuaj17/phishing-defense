import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from engine import fetcher
from engine.fetcher import BlockedURL, fetch_page, validate_url

REAL_VALIDATE = fetcher.validate_url


class GuardTests(unittest.TestCase):
    def test_blocks_internal_and_odd_targets(self):
        blocked = [
            "http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/", "http://192.168.1.1/", "http://172.16.0.1/", "http://[::1]/",
            "http://[::ffff:127.0.0.1]/", "http://2130706433/", "http://0.0.0.0/",
            "file:///etc/passwd", "ftp://example.com/", "gopher://example.com/",
            "http://user:pw@93.184.216.34/", "http://93.184.216.34:8080/", "http://93.184.216.34:22/",
            "http:///nohost",
        ]
        for url in blocked:
            with self.subTest(url=url), self.assertRaises(BlockedURL):
                validate_url(url)

    def test_allows_public_ip_literal(self):
        self.assertEqual(validate_url("http://93.184.216.34/x"), "http://93.184.216.34/x")
        self.assertEqual(validate_url("https://93.184.216.34/"), "https://93.184.216.34/")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if self.path == "/ok":
            self._send(200, "text/html; charset=utf-8", b"<html><title>hi</title><body>hello</body></html>")
        elif self.path == "/redir-internal":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
        elif self.path == "/redir-ok":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
        elif self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
        elif self.path == "/json":
            self._send(200, "application/json", b"{}")
        elif self.path == "/big":
            self._send(200, "text/html", b"<p>" + b"x" * 50_000)
        else:
            self._send(404, "text/html", b"nope")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

        def validator(url):  # allow only our test server, everything else goes through the real guard
            sp = urlsplit(url)
            if sp.hostname == "127.0.0.1" and sp.port == cls.port:
                return url
            return REAL_VALIDATE(url)

        fetcher.validate_url = validator

    @classmethod
    def tearDownClass(cls):
        fetcher.validate_url = REAL_VALIDATE
        cls.server.shutdown()
        cls.server.server_close()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_fetches_html(self):
        r = fetch_page(self.url("/ok"))
        self.assertTrue(r.ok)
        self.assertIn("hello", r.html)

    def test_follows_safe_redirect(self):
        r = fetch_page(self.url("/redir-ok"))
        self.assertTrue(r.ok)
        self.assertEqual(r.redirects, 1)
        self.assertTrue(r.final_url.endswith("/ok"))

    def test_redirect_to_internal_address_is_blocked(self):
        r = fetch_page(self.url("/redir-internal"))
        self.assertFalse(r.ok)
        self.assertTrue(r.blocked)

    def test_redirect_loop_stops(self):
        r = fetch_page(self.url("/loop"))
        self.assertFalse(r.ok)
        self.assertIn("redirect", r.error.lower())

    def test_non_html_is_rejected(self):
        self.assertFalse(fetch_page(self.url("/json")).ok)

    def test_body_is_capped(self):
        old = fetcher.MAX_BYTES
        fetcher.MAX_BYTES = 10_000
        try:
            r = fetch_page(self.url("/big"))
        finally:
            fetcher.MAX_BYTES = old
        self.assertTrue(r.ok)
        self.assertLess(len(r.html), 30_000)


if __name__ == "__main__":
    unittest.main()
