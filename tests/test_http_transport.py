"""Real WinHTTP against a controlled loopback server; no provider keys/network required."""
import http.server
import os
from pathlib import Path
import subprocess
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "nt", "WinHTTP runtime tests require Windows")
class HttpTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = ROOT / "build" / "http_test_driver.exe"
        if not cls.driver.is_file():
            raise RuntimeError("Compile tests/http_test_driver.cpp with src/http.cpp first")
        cls.paths = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                cls.paths.append(self.path)
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                status, body, length = 200, self.path.encode(), None
                if self.path == "/redirect":
                    status, body = 302, b""
                elif self.path == "/truncated":
                    body, length = b"short", 100
                elif self.path == "/large":
                    body = b"x" * (2 * 1024 * 1024 + 1)
                elif self.path == "/limit":
                    body = b"x" * (2 * 1024 * 1024)
                elif self.path == "/failure":
                    status = 503
                self.send_response(status)
                self.send_header("Content-Length", len(body) if length is None else length)
                if status == 302:
                    self.send_header("Location", "/leaked")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # bounded client deliberately closes an oversized response

        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, path, key="fixture-key"):
        url = path if path.startswith("http") else self.base + path
        result = subprocess.run([str(self.driver), url, key], capture_output=True, text=True, timeout=15, check=True)
        ok, status, size, error, body = result.stdout.split("\n", 4)
        return bool(int(ok)), int(status), int(size), error, body

    def test_query_parameters_are_not_lost(self):
        result = self.request("/echo?api-version=2026&x=1")
        self.assertTrue(result[0])
        self.assertEqual(result[4], "/echo?api-version=2026&x=1")

    def test_redirect_does_not_forward_key_or_body(self):
        before = len(self.paths)
        result = self.request("/redirect")
        self.assertFalse(result[0])
        self.assertEqual(result[1], 302)
        self.assertEqual(self.paths[before:], ["/redirect"])

    def test_truncated_200_is_not_success(self):
        result = self.request("/truncated")
        self.assertFalse(result[0])
        self.assertEqual(result[2], 0)
        self.assertEqual(result[3], "incomplete response")

    def test_oversized_200_is_not_success(self):
        result = self.request("/large")
        self.assertFalse(result[0])
        self.assertEqual(result[2], 0)
        self.assertEqual(result[3], "response too large")

    def test_exact_limit_is_accepted(self):
        result = self.request("/limit")
        self.assertTrue(result[0])
        self.assertEqual(result[2], 2 * 1024 * 1024)

    def test_http_failure_is_not_success(self):
        result = self.request("/failure")
        self.assertFalse(result[0])
        self.assertEqual(result[1], 503)

    def test_remote_plaintext_rejected_before_network(self):
        result = self.request("http://example.invalid/v1")
        self.assertFalse(result[0])
        self.assertEqual(result[1], 0)
        self.assertIn("HTTPS required", result[3])

    def test_header_injection_rejected_before_network(self):
        before = len(self.paths)
        result = self.request("/echo", "bad\r\nInjected: yes")
        self.assertFalse(result[0])
        self.assertEqual(result[3], "invalid header value")
        self.assertEqual(len(self.paths), before)
