"""OWSI internal test website (spec §101) + test certificate environment (§102).

A deliberately feature-complete local lab target used by the automated test
suite and for manual testing. It NEVER contacts the internet — every route
serves locally generated content.

Routes:
    /                 landing page (HTML, Server header)
    /login            POST form login → sets session cookie + JWT
    /logout           clears session cookie
    /api/user         JSON user object (auth-gated via Bearer JWT)
    /api/items        JSON list
    /api/error        500 with JSON error body
    /api/headers      echoes request headers as JSON
    /api/cookie       sets a cookie, echoes cookies
    /api/json         accepts & reflects JSON
    /api/form         accepts urlencoded form
    /websocket        real WebSocket endpoint (RFC 6455 echo/broadcast)
    /redirect         302 → /
    /large-response   ~2 MB body
    /binary           raw binary payload
    /gzip             gzip-compressed response
    /chunked          chunked transfer encoding

Usage:
    python -m owsi.testsite --port 8642 [--https-port 8643] [--data-dir DIR]
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import hmac
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse

from .ca import CertificateAuthority

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SECRET = b"owsi-test-site-secret"


def make_jwt(payload: dict) -> str:
    def b64u(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    header = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64u(json.dumps(payload).encode())
    sig = b64u(hmac.new(SECRET, f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


# --------------------------------------------------------------------------
# minimal HTTP/1.1 server on raw sockets (stdlib only, threaded)
class TestSite:
    def __init__(self, host: str = "127.0.0.1", port: int = 8642,
                 https_port: int = 0, data_dir: str = ""):
        self.host = host
        self.port = port
        self.https_port = https_port
        self._srv: list[socket.socket] = []
        self._running = False
        self._lock = threading.Lock()
        self.ws_sessions = 0
        self.requests_seen = 0
        self.data_dir = data_dir or os.path.join(os.getcwd(), ".testsite")
        self._tls_ctx: ssl.SSLContext | None = None
        if https_port:
            os.makedirs(self.data_dir, exist_ok=True)
            ca = CertificateAuthority(os.path.join(self.data_dir, "ca"))
            cert_pem, key_pem = ca.leaf_for_host(host)
            cpath = os.path.join(self.data_dir, "site.crt")
            kpath = os.path.join(self.data_dir, "site.key")
            with open(cpath, "wb") as f:
                f.write(cert_pem)
            with open(kpath, "wb") as f:
                f.write(key_pem)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cpath, kpath)
            self._tls_ctx = ctx

    # ------------------------------------------------------------- lifecycle
    def start(self) -> tuple[int, int]:
        s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s4.bind((self.host, self.port))
        s4.listen(64)
        self.port = s4.getsockname()[1]
        self._srv.append(s4)
        self._running = True
        threading.Thread(target=self._accept, args=(s4, False),
                         daemon=True, name="testsite-http").start()
        if self._tls_ctx:
            s6 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s6.bind((self.host, self.https_port))
            self.https_port = s6.getsockname()[1]
            self._srv.append(s6)
            threading.Thread(target=self._accept, args=(s6, True),
                             daemon=True, name="testsite-https").start()
        return self.port, self.https_port

    def stop(self) -> None:
        self._running = False
        for s in self._srv:
            try:
                s.close()
            except OSError:
                pass

    def _accept(self, srv: socket.socket, tls: bool) -> None:
        while self._running:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            if tls and self._tls_ctx:
                try:
                    conn = self._tls_ctx.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError):
                    conn.close()
                    continue
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()

    # ------------------------------------------------------------- protocol
    @staticmethod
    def _read_head(sock) -> bytes | None:
        buf = b""
        while b"\r\n\r\n" not in buf:
            try:
                c = sock.recv(4096)
            except OSError:
                return None
            if not c:
                return None
            buf += c
            if len(buf) > 262144:
                return None
        return buf

    def _handle(self, conn: socket.socket) -> None:
        try:
            while True:
                head = self._read_head(conn)
                if not head:
                    return
                line, _, hdr_blob = head.partition(b"\r\n")
                parts = line.decode("latin1").split(" ")
                if len(parts) < 2:
                    return
                method, target = parts[0], parts[1]
                headers = {}
                for hl in hdr_blob.split(b"\r\n"):
                    if not hl.strip():
                        continue
                    k, _, v = hl.decode("latin1").partition(":")
                    headers[k.strip().lower()] = v.strip()
                body = b""
                cl = int(headers.get("content-length") or 0)
                rest = head.split(b"\r\n\r\n", 1)[1]
                body = rest[:cl]
                while len(body) < cl:
                    c = conn.recv(min(65536, cl - len(body)))
                    if not c:
                        break
                    body += c
                with self._lock:
                    self.requests_seen += 1
                up = urllib.parse.urlsplit(target)
                # WebSocket upgrade?
                if (headers.get("upgrade") or "").lower() == "websocket":
                    self._ws_handle(conn, up.path, headers)
                    return
                keep = (headers.get("connection") or "").lower() != "close" \
                    and parts[-1].startswith("HTTP/1.1")
                self._route(conn, method, up.path, up.query, headers, body,
                            keep_alive=keep)
                if not keep:
                    return
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _send(conn, status: str, headers: dict[str, str], body: bytes,
              http_version: str = "HTTP/1.1") -> None:
        out = f"{http_version} {status}\r\n".encode("latin1")
        hd = dict(headers)
        if "Content-Length" not in hd and "Transfer-Encoding" not in hd:
            hd["Content-Length"] = str(len(body))
        for k, v in hd.items():
            out += f"{k}: {v}\r\n".encode("latin1")
        conn.sendall(out + b"\r\n" + body)

    # ------------------------------------------------------------- routes
    def _route(self, conn, method: str, path: str, query: str,
               headers: dict, body: bytes, keep_alive: bool = True) -> None:
        H = {"Connection": "keep-alive" if keep_alive else "close"}
        q = urllib.parse.parse_qs(query)
        json_h = {**H, "Content-Type": "application/json"}
        html_h = {**H, "Content-Type": "text/html; charset=utf-8",
                  "Server": "OWSI-TestSite/1.0"}
        if path == "/":
            page = (b"<html><head><title>OWSI Test Site</title></head><body>"
                    b"<h1>OWSI internal test site</h1>"
                    b"<p>Labs routes: /login /logout /api/* /websocket "
                    b"/redirect /large-response /binary /gzip /chunked</p>"
                    b"<script>fetch('/api/items');</script></body></html>")
            return self._send(conn, "200 OK", html_h, page)
        if path == "/login":
            if method != "POST":
                page = (b"<form method=post action=/login>"
                        b"<input name=username value=admin>"
                        b"<input name=password type=password value=hunter2>"
                        b"<button>Login</button></form>")
                return self._send(conn, "200 OK", html_h, page)
            form = urllib.parse.parse_qs(body.decode("utf-8", "replace"),
                                         keep_blank_values=True)
            user = (form.get("username") or [""])[0]
            jwt = make_jwt({"sub": user or "anonymous",
                            "exp": int(time.time()) + 3600, "role": "user"})
            h = {**html_h,
                 "Set-Cookie": f"session={jwt}; Path=/; HttpOnly",
                 "Location": "/api/user"}
            return self._send(conn, "302 Found", h, b"")
        if path == "/logout":
            h = {**json_h, "Set-Cookie": "session=; Path=/; Max-Age=0"}
            return self._send(conn, "200 OK", h, b'{"loggedOut": true}')
        if path == "/api/user":
            auth = headers.get("authorization") or ""
            cookie = headers.get("cookie") or ""
            token = auth.removeprefix("Bearer ").strip()
            if not token and "session=" in cookie:
                token = cookie.split("session=", 1)[1].split(";")[0]
            if not token:
                return self._send(conn, "401 Unauthorized",
                                  {**json_h, "WWW-Authenticate": "Bearer"},
                                  b'{"error":"unauthenticated"}')
            try:
                payload_b64 = token.split(".")[1]
                payload_b64 += "=" * (-len(payload_b64) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            except Exception:
                return self._send(conn, "400 Bad Request", json_h,
                                  b'{"error":"bad token"}')
            return self._send(conn, "200 OK", json_h, json.dumps(
                {"id": 1, "username": payload.get("sub", "?"),
                 "role": payload.get("role", "user"),
                 "email": "lab@localhost"}).encode())
        if path == "/api/items":
            return self._send(conn, "200 OK", json_h, json.dumps(
                [{"id": i, "name": f"item-{i}"} for i in range(1, 6)]).encode())
        if path == "/api/error":
            return self._send(conn, "500 Internal Server Error", json_h,
                              b'{"error":"kaboom","trace":"fake-trace"}')
        if path == "/api/headers":
            return self._send(conn, "200 OK", json_h,
                              json.dumps(headers).encode())
        if path == "/api/cookie":
            h = {**json_h,
                 "Set-Cookie": "testcookie=hello; Path=/; SameSite=Lax"}
            return self._send(conn, "200 OK", h,
                              json.dumps({"cookies": headers.get("cookie", "")})
                              .encode())
        if path == "/api/json":
            try:
                obj = json.loads(body.decode() or "{}")
            except Exception:
                return self._send(conn, "400 Bad Request", json_h,
                                  b'{"error":"invalid json"}')
            return self._send(conn, "200 OK", json_h,
                              json.dumps({"echo": obj}).encode())
        if path == "/api/form":
            form = urllib.parse.parse_qs(body.decode("utf-8", "replace"),
                                         keep_blank_values=True)
            return self._send(conn, "200 OK", json_h,
                              json.dumps({"echo": {k: v[0] for k, v in
                                                   form.items()}}).encode())
        if path == "/redirect":
            return self._send(conn, "302 Found",
                              {**H, "Location": "/"}, b"")
        if path == "/large-response":
            blob = b"L" * (2 * 1024 * 1024)
            return self._send(conn, "200 OK",
                              {**H, "Content-Type": "application/octet-stream"},
                              blob)
        if path == "/binary":
            blob = bytes(range(256)) * 4
            return self._send(conn, "200 OK",
                              {**H, "Content-Type": "application/octet-stream"},
                              blob)
        if path == "/gzip":
            raw = gzip.compress(b"compressed payload for OWSI decoding tests " * 10)
            return self._send(conn, "200 OK",
                              {**H, "Content-Type": "text/plain",
                               "Content-Encoding": "gzip"}, raw)
        if path == "/chunked":
            out = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n" \
                  b"Content-Type: text/plain\r\nConnection: close\r\n\r\n"
            for i in range(5):
                chunk = f"chunk-{i}\n".encode()
                out += f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
            out += b"0\r\n\r\n"
            conn.sendall(out)
            return
        self._send(conn, "404 Not Found", json_h, b'{"error":"no such route"}')

    # ------------------------------------------------------------- websocket
    def _ws_handle(self, conn, path: str, headers: dict) -> None:
        key = headers.get("sec-websocket-key", "")
        accept = base64.b64encode(hashlib.sha1(
            key.encode() + WS_GUID).digest()).decode()
        conn.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                      "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
        with self._lock:
            self.ws_sessions += 1
        # echo loop: reply to each text frame with "ack:<msg>", send hello
        def frame(opcode: int, payload: bytes) -> bytes:
            hdr = bytearray([0x80 | opcode])
            ln = len(payload)
            if ln < 126:
                hdr.append(ln)
            elif ln < 65536:
                hdr.append(126); hdr += struct.pack("!H", ln)
            else:
                hdr.append(127); hdr += struct.pack("!Q", ln)
            return bytes(hdr) + payload
        conn.sendall(frame(0x1, b'{"hello":"owsi test ws"}'))
        try:
            while True:
                b0 = conn.recv(1)
                if not b0:
                    return
                b1 = conn.recv(1)
                if not b1:
                    return
                opcode = b0[0] & 0x0F
                masked = b1[0] & 0x80
                ln = b1[0] & 0x7F
                if ln == 126:
                    ln = int.from_bytes(self._recv_exact(conn, 2), "big")
                elif ln == 127:
                    ln = int.from_bytes(self._recv_exact(conn, 8), "big")
                mask = self._recv_exact(conn, 4) if masked else b""
                data = self._recv_exact(conn, ln)
                if masked:
                    data = bytes(d ^ mask[i % 4] for i, d in enumerate(data))
                if opcode == 0x8:
                    conn.sendall(frame(0x8, b""))
                    return
                if opcode in (0x1, 0x2):
                    conn.sendall(frame(opcode, b"ack:" + data))
        except OSError:
            pass

    @staticmethod
    def _recv_exact(sock, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            c = sock.recv(n - len(buf))
            if not c:
                raise OSError("closed")
            buf += c
        return buf


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="owsi-testsite")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8642)
    ap.add_argument("--https-port", type=int, default=8643)
    ap.add_argument("--data-dir", default="")
    ap.add_argument("--duration", type=float, default=0,
                    help="seconds to run (0 = until Ctrl-C)")
    a = ap.parse_args(argv)
    site = TestSite(a.host, a.port, a.https_port, a.data_dir)
    p, hp = site.start()
    print(f"test site:  http://{a.host}:{p}")
    if hp:
        print(f"test site:  https://{a.host}:{hp}  (OWSI CA-signed cert)")
    try:
        if a.duration:
            time.sleep(a.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        site.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
