"""Fault-injection mock: HTTP server that always answers 429 Too Many Requests.

Used to verify the SKILL.md rule that a 429 must stop the tool immediately,
with no retry and no backoff wait.

Usage: python 429server.py [port]   (default 8079)
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8079


class Always429(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(429)
        self.send_header("Retry-After", "3600")
        self.end_headers()
        self.wfile.write(b"429 too many requests (mock)")

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", PORT), Always429).serve_forever()
