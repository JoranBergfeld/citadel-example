"""Throwaway fixture-only UI. Run: python3 src/citadel/operator/team_demo_prototype.py"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit


class PrototypeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if urlsplit(self.path).path not in ("/", "/team-demo-prototype"):
            self.send_error(404)
            return
        content = Path(__file__).with_suffix(".html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


if __name__ == "__main__":
    print("Fixture-only prototype: http://127.0.0.1:8765/team-demo-prototype", flush=True)
    HTTPServer(("127.0.0.1", 8765), PrototypeHandler).serve_forever()
