#!/usr/bin/env python3
"""Loopback fixtures for testing the kit — these are TEST TARGETS, not attacks.

Four tiny servers on 127.0.0.1, all started by this one file:

  :8080  plain HTTP — a throttled endpoint + a fake WP install:
           /app                    per-client limiter: first 3 GETs -> 200,
                                   then 429 + Retry-After. Requests carrying
                                   any IP-override header (X-Forwarded-For,
                                   X-Real-IP, X-Originating-IP, X-Client-IP,
                                   CF-Connecting-IP) always -> 200, so the
                                   bypass tools have something real to find.
           /app with HEAD/OPTIONS  always 200 (unthrottled methods).
           /open                   always 200 (NO-LIMITER baseline target).
           / + /wp-json/...        fake WP fixture: generator meta, users REST,
                                   readme, xmlrpc, uploads listing, CORS *,
                                   versioned Server banner, zero sec headers.
           anything else           404 (so case-path style variants show
                                   INEFFECTIVE, not false BYPASSED).
  :8443  same fixture over TLS (self-signed cert, generated on first run).
  :12525 TCP banner stub ("SSH-2.0-TestStub").
  :15353 UDP echo stub (replies b"echo:"+payload).

Run:  python3 tests/stubs.py          # foreground, Ctrl-C to stop
        (each server runs in its own thread; READY line when all are up)

#test-fixtures #loopback-only #not-an-attack
"""
import os
import posixpath
import socket
import ssl
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "test-cert.pem")

HTTP_PORT = 8080
TLS_PORT = 8443
BANNER_PORT = 12525
UDP_PORT = 15353

BYPASS_HEADERS = {"x-forwarded-for", "x-real-ip", "x-originating-ip",
                  "x-client-ip", "cf-connecting-ip"}
LIMIT = 3  # first N plain GETs per client IP succeed, then 429

USERS_JSON = ('[{"id":1,"slug":"admin"},{"id":2,"slug":"editor"}]').encode()
HOME_PAGE = ("""<html><head>
<meta name="generator" content="WordPress 6.4.1" />
</head><body>fixture</body></html>""").encode()


def ensure_cert():
    if os.path.exists(CERT):
        return
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", CERT, "-out", CERT, "-days", "2", "-nodes",
                    "-subj", "/CN=127.0.0.1"],
                   check=True, capture_output=True)


class Fixture(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Apache/2.4.41"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _common_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Server", "Apache/2.4.41")
        self.send_header("X-Powered-By", "PHP/7.4.3")

    def _send(self, code, body=b"", extra=None):
        self.send_response(code)
        self._common_headers()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _has_bypass_header(self):
        return any(k.lower() in BYPASS_HEADERS for k in self.headers)

    def _limited_app(self):
        """429 logic for GET /app. Returns (code, body, extra_headers)."""
        if self._has_bypass_header():
            return 200, b"ok-bypassed", {}
        ip = self.client_address[0]
        counts = self.server.limiter
        counts[ip] = counts.get(ip, 0) + 1
        if counts[ip] <= LIMIT:
            return 200, b"ok", {}
        return 429, b"rate limited", {"Retry-After": "2"}

    def _route(self):
        path = posixpath.normpath(urllib.parse.urlparse(self.path).path)
        if path == "/app":
            if self.command in ("HEAD", "OPTIONS"):
                return 200, b"", {"Allow": "GET, HEAD, OPTIONS, TRACE"}
            code, body, extra = self._limited_app()
            return code, body, extra
        if path == "/open":
            return 200, b"open", {}
        if path == "/":
            return 200, HOME_PAGE, {"Content-Type": "text/html"}
        if path == "/wp-json/wp/v2/users":
            return 200, USERS_JSON, {"Content-Type": "application/json"}
        if path == "/readme.html":
            return 200, b"WordPress readme", {"Content-Type": "text/html"}
        if path == "/xmlrpc.php":
            return 200, b"XML-RPC server accepts POST requests only.", {}
        if path == "/wp-content/uploads":
            return 200, b"<html><head><title>Index of /wp-content/uploads/</title></head></html>", {}
        return 404, b"nope", {}

    def _handle(self):
        if self.command == "TRACE":
            echo = (self.requestline + "\r\n" + str(self.headers)).encode()
            self._send(200, echo, {"Content-Type": "message/http"})
            return
        if self.command == "OPTIONS" and self.path.rstrip("/") != "/app":
            self._send(200, b"", {"Allow": "GET, HEAD, OPTIONS, TRACE"})
            return
        code, body, extra = self._route()
        ctype = extra.pop("Content-Type", None) if isinstance(extra, dict) else None
        headers = dict(extra) if isinstance(extra, dict) else {}
        if ctype:
            headers["Content-Type"] = ctype
        self._send(code, body, headers)

    do_GET = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle
    do_TRACE = _handle


def serve_http():
    srv = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), Fixture)
    srv.limiter = {}
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def serve_tls():
    ensure_cert()
    srv = ThreadingHTTPServer(("127.0.0.1", TLS_PORT), Fixture)
    srv.limiter = {}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, CERT)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def serve_banner():
    def loop():
        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(("127.0.0.1", BANNER_PORT))
        ls.listen(10)
        while True:
            c, _ = ls.accept()
            try:
                c.sendall(b"SSH-2.0-TestStub_1.0\r\n")
                threading.Event().wait(2)
            except OSError:
                pass
            finally:
                c.close()
    threading.Thread(target=loop, daemon=True).start()


def serve_udp():
    def loop():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", UDP_PORT))
        while True:
            data, addr = s.recvfrom(4096)
            s.sendto(b"echo:" + data, addr)
    threading.Thread(target=loop, daemon=True).start()


def main():
    serve_http()
    serve_tls()
    serve_banner()
    serve_udp()
    print(f"READY http={HTTP_PORT} tls={TLS_PORT} banner={BANNER_PORT} "
          f"udp={UDP_PORT}", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    sys.exit(main())
