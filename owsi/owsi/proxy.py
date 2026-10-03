"""MITM HTTP/HTTPS proxy — the real interception engine (spec 15/16).

Handles:
  * absolute-URI requests for plain HTTP proxying
  * CONNECT tunnels with TLS termination using the OWSI CA (HTTPS interception)
  * WebSocket Upgrade → hands socket to the WS relay engine
  * request/response interception hooks, rules engine, logging, history
Single-threaded-per-connection ThreadingHTTP-style server (socketserver).
"""
from __future__ import annotations

import select
import socket
import ssl
import threading
import time
from typing import Optional

from .ca import CertificateAuthority
from .http_client import send_request
from .http_model import CRLF, HeaderList, HttpRequest, HttpResponse, parse_headers

PROXY_VERSION = "OWSI/1.0"


def _status_line(code: int, reason: str = "") -> bytes:
    return f"HTTP/1.1 {code} {reason or _REASONS.get(code, '')}\r\n".encode()


_REASONS = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found",
            502: "Bad Gateway", 508: "Loop Detected"}


def _simple_response(sock: socket.socket, code: int, body: bytes = b"",
                    ctype: str = "text/plain") -> None:
    resp = _status_line(code)
    resp += f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
    resp += f"Connection: close\r\nProxy-Agent: {PROXY_VERSION}\r\n\r\n".encode()
    try:
        sock.sendall(resp + body)
    except OSError:
        pass


class ProxyHandler(threading.Thread):
    daemon = True

    def __init__(self, conn: socket.socket, engine: "ProxyEngine"):
        super().__init__()
        self.conn = conn
        self.engine = engine
        self.client: socket.socket = conn   # becomes TLS-wrapped socket on MITM

    # ------------------------------------------------------------------ helpers
    def _read_head(self, sock) -> Optional[bytes]:
        buf = b""
        while CRLF + CRLF not in buf:
            try:
                chunk = sock.recv(4096)
            except (OSError, ssl.SSLError):
                return None
            if not chunk:
                return None
            buf += chunk
            if len(buf) > 262144:
                return None
        return buf

    def _read_body(self, sock, req: HttpRequest, head_buf: bytes) -> bytes:
        consumed = head_buf.split(CRLF + CRLF, 1)[1] if CRLF + CRLF in head_buf else b""
        te = (req.headers.get("Transfer-Encoding") or "").lower()
        cl = req.headers.get("Content-Length")
        if "chunked" in te:
            data = consumed
            body = b""
            while True:
                while CRLF not in data:
                    more = sock.recv(4096)
                    if not more:
                        return body
                    data += more
                size_tok, _, data = data.partition(CRLF)
                try:
                    sz = int(size_tok.split(b";")[0], 16)
                except ValueError:
                    return body
                if sz == 0:
                    break
                while len(data) < sz + 2:
                    more = sock.recv(max(4096, sz + 2 - len(data)))
                    if not more:
                        return body
                    data += more
                body += data[:sz]
                data = data[sz + 2:]
                if len(body) > self.engine.policy.limits.max_body_size:
                    return body
            return body
        if cl and cl.isdigit():
            want = int(cl)
            data = consumed
            while len(data) < want:
                more = sock.recv(min(65536, want - len(data)))
                if not more:
                    break
                data += more
                if len(data) > self.engine.policy.limits.max_body_size:
                    break
            return data[:want]
        return b""

    # ------------------------------------------------------------------ main
    def run(self) -> None:
        try:
            self._serve_loop_plain(self.conn, scheme_hint="http")
        except Exception as e:
            self.engine.log(f"handler error: {type(e).__name__}: {e}")
        finally:
            try:
                self.conn.close()
            except OSError:
                pass

    def _serve_loop_plain(self, sock, scheme_hint: str) -> None:
        """Serve requests over `sock` until close / upgrade / tunnel handoff."""
        while True:
            head_buf = self._read_head(sock)
            if not head_buf:
                return
            first_line = head_buf.split(CRLF, 1)[0].decode("iso-8859-1")
            parts = first_line.split(" ")
            if len(parts) < 3:
                _simple_response(sock, 400, b"malformed request line")
                return
            method, target, version = parts[0], parts[1], parts[2]
            headers, consumed = parse_headers(head_buf.split(CRLF, 1)[1])
            raw_rest = head_buf.split(CRLF + CRLF, 1)[1] if CRLF + CRLF in head_buf else b""

            if method.upper() == "CONNECT":
                host_port = target
                host = host_port.rsplit(":", 1)[0]
                port = int(host_port.rsplit(":", 1)[1]) if ":" in host_port else 443
                self._handle_connect(sock, host, port)
                return

            req = HttpRequest(method=method, target=target, version=version,
                              headers=headers)
            if "://" in target:
                from urllib.parse import urlsplit
                sp = urlsplit(target)
                req.scheme, req.host = sp.scheme, sp.hostname or ""
                req.port = sp.port or (443 if sp.scheme == "https" else 80)
                req.target = (sp.path or "/") + (("?" + sp.query) if sp.query else "")
            else:
                req.scheme = scheme_hint
                host_hdr = headers.get("Host") or ""
                req.host = host_hdr.split(":")[0]
                try:
                    req.port = int(host_hdr.rsplit(":", 1)[1]) if ":" in host_hdr \
                        else (443 if scheme_hint == "https" else 80)
                except (ValueError, IndexError):
                    req.port = 80 if scheme_hint == "http" else 443
            req.body = self._read_body_from(sock, head_buf, consumed, req)

            # WebSocket upgrade over plain HTTP proxying? Hand the raw socket
            # to the WS relay engine (it opens upstream and forwards frames).
            if (req.headers.get("Upgrade") or "").lower() == "websocket" \
                    and req.scheme == "http":
                self.engine.handle_websocket_upgrade(sock, req)
                return

            resp = self.engine.process_http(req, client_sock=sock)
            if resp is None:          # dropped at intercept
                _simple_response(sock, 508, b"Request dropped by OWSI interceptor")
                return
            try:
                sock.sendall(resp.raw())
            except OSError:
                return
            keep = (resp.headers.get("Connection") or "").lower() != "close" and \
                   (headers.get("Connection") or "").lower() != "close"
            if not keep:
                return

    def _read_body_from(self, sock, head_buf, hdr_consumed, req) -> bytes:
        # reconstruct remainder after header terminator
        idx = head_buf.find(CRLF + CRLF)
        rest = head_buf[idx + 4:] if idx >= 0 else b""
        fake = _MemSock(rest, sock)
        return self._read_body(fake, req, head_buf)

    # ------------------------------------------------------------------ HTTPS
    def _handle_connect(self, client_sock, host: str, port: int) -> None:
        self.engine.log(f"CONNECT {host}:{port}")
        if not self.engine.intercept_https:
            # blind tunnel (no MITM)
            try:
                up = socket.create_connection((host, port),
                                              self.engine.policy.limits.timeout_sec)
            except OSError as e:
                _simple_response(client_sock, 502, str(e).encode())
                return
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.engine.tunnel(client_sock, up)
            up.close()
            return

        # Read the first record(s) from the tunnelled connection to decide how
        # to handle it:
        #   * TLS ClientHello without an "http/*" ALPN (e.g. wss://) → blind
        #     tunnel — browsers negotiate "websocket" via ALPN directly, so
        #     MITM would break the connection anyway.
        #   * anything else (plain HTTP sent through a CONNECT tunnel, or a
        #     normal https:// ClientHello) → MITM interception.
        def _alpn_protocols(ch: bytes) -> list[str]:
            """Extract ALPN protocol names from a raw ClientHello message body."""
            out: list[str] = []
            try:
                rest = ch[35:]              # skip msg-type+ver(3) + random(32)
                pos = 0
                sid_len = rest[pos]; pos += 1 + sid_len
                cs_len = int.from_bytes(rest[pos:pos + 2], "big"); pos += 2 + cs_len
                comp_len = rest[pos]; pos += 1 + comp_len
                ext_len = int.from_bytes(rest[pos:pos + 2], "big"); pos += 2
                exts = rest[pos:pos + ext_len]
                i = 0
                while i + 4 <= len(exts):
                    etype = int.from_bytes(exts[i:i + 2], "big")
                    elen = int.from_bytes(exts[i + 2:i + 4], "big")
                    data = exts[i + 4:i + 4 + elen]
                    if etype == 0x3376:     # ALPN protocol list
                        j = 0
                        while j < len(data):
                            ln = data[j]
                            out.append(data[j + 1:j + 1 + ln].decode(
                                "latin1", "replace"))
                            j += 1 + ln
                    i += 4 + elen
            except Exception:
                pass
            return out

        pre = b""
        try:
            client_sock.settimeout(3.0)
            while True:                      # accumulate one full TLS record
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                pre += chunk
                if pre[:1] != b"\x16":       # not a handshake record — stop
                    break
                rec_len = int.from_bytes(pre[1:3], "big") if len(pre) >= 3 else 0
                if len(pre) >= 3 + rec_len:
                    break
                if len(pre) > 65536:
                    break
            client_sock.settimeout(None)
        except (OSError, ssl.SSLError):
            pass

        if pre[:1] == b"\x16":               # TLS handshake record
            rec_len = int.from_bytes(pre[1:3], "big") if len(pre) >= 3 else 0
            if len(pre) >= 3 + rec_len and rec_len > 0:
                ch = pre[3:3 + rec_len]
                if ch[:1] == b"\x01":        # ClientHello
                    alpn = _alpn_protocols(ch)
                    if alpn and not any(p.startswith("http/") for p in alpn):
                        # wss:// style — tunnel blind, never MITM-break it
                        try:
                            up = socket.create_connection(
                                (host, port),
                                self.engine.policy.limits.timeout_sec)
                        except OSError as e:
                            _simple_response(client_sock, 502, str(e).encode())
                            return
                        client_sock.sendall(
                            b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        self.engine.log(f"CONNECT {host}:{port}: non-HTTP ALPN "
                                        f"{alpn} → blind tunnel")
                        if pre:
                            up.sendall(pre)
                        self.engine.tunnel(client_sock, up)
                        up.close()
                        return

        # MITM: terminate TLS with a CA-signed leaf for this host
        cert_pem, key_pem = self.engine.ca.leaf_for_host(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        import tempfile, os
        cpath = os.path.join(tempfile.gettempdir(), f"owsi-{abs(hash(host))}.crt")
        kpath = cpath.replace(".crt", ".key")
        for p, blob in ((cpath, cert_pem), (kpath, key_pem)):
            if not os.path.exists(p):
                with open(p, "wb") as f:
                    f.write(blob)
        try:
            ctx.load_cert_chain(cpath, kpath)
        except ssl.SSLError as e:
            self.engine.log(f"leaf load failed for {host}: {e}")
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            try:
                up = socket.create_connection((host, port), 10)
                self.engine.tunnel(client_sock, up)
                up.close()
            finally:
                return
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        try:
            tls = ctx.wrap_socket(client_sock, server_side=True)
        except (ssl.SSLError, OSError) as e:
            self.engine.log(f"TLS handshake failed for {host}: {e}")
            return
        self.engine.log(f"intercepted TLS session to {host}:{port}")
        try:
            self._serve_loop_plain(tls, scheme_hint="https")
        finally:
            tls.close()


class _MemSock:
    """Read helper: drain prefetched bytes first, then the real socket."""

    def __init__(self, pre: bytes, sock):
        self.pre = pre
        self.sock = sock

    def recv(self, n: int) -> bytes:
        if self.pre:
            out, self.pre = self.pre[:n], self.pre[n:]
            return out
        return self.sock.recv(n)


# ---------------------------------------------------------------------------
class ProxyEngine:
    def __init__(self, app):
        self.app = app                      # shared Application context
        self.policy = app.policy
        self.interceptor = app.interceptor
        self.rules = app.rules
        self.db = app.db
        self.bus = app.bus
        self.ca: CertificateAuthority = app.ca
        self.intercept_https = True
        self.listen_addr = ("127.0.0.1", 8080)
        self._srv: Optional[socket.socket] = None
        self._running = False
        self.request_count = 0
        self.log_lines: list[str] = []
        # live client sockets so stop() can unblock handlers stuck in recv()
        self._live_conns: set = set()
        self._conns_lock = threading.Lock()

    # ------------------------------------------------------------------
    def log(self, msg: str) -> None:
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        self.log_lines.append(line)
        if len(self.log_lines) > 1000:
            del self.log_lines[:-1000]
        self.bus.publish("proxy.log", {"line": line})

    def start(self, addr=("127.0.0.1", 8080)) -> None:
        self.listen_addr = addr
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(addr)
        srv.listen(128)
        self._srv = srv
        self._running = True
        t = threading.Thread(target=self._accept_loop, daemon=True, name="owsi-proxy")
        t.start()
        self.log(f"proxy listening on http://{addr[0]}:{addr[1]}")

    def stop(self) -> None:
        self._running = False
        if self._srv:
            try:
                self._srv.close()
            except OSError:
                pass
        # unblock any handlers stuck in recv() on idle keep-alive sockets
        with self._conns_lock:
            live = list(self._live_conns)
            self._live_conns.clear()
        for s in live:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def _track(self, conn, add: bool) -> None:
        with self._conns_lock:
            if add:
                self._live_conns.add(conn)
            else:
                self._live_conns.discard(conn)

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                break
            h = ProxyHandler(conn, self)
            h.daemon = True
            h.start()

    # ------------------------------------------------------------------
    def process_http(self, req: HttpRequest, client_sock=None) -> Optional[HttpResponse]:
        """Full pipeline: rules → intercept → policy → forward → analyze → log."""
        req.source = "proxy"
        self.request_count += 1

        dropped, rlogs = self.rules.apply("request", req)
        for l in rlogs:
            self.log(l)
        if dropped:
            self.record(req, HttpResponse(status=0, error="dropped by rule"),
                        extra_tags=["rule-drop"])
            return None

        action, final_req = self.interceptor.intercept_request(req)
        if action == "drop":
            self.record(req, HttpResponse(status=0, error="dropped at intercept"),
                        extra_tags=["intercept-drop"])
            return None
        req = final_req

        # Policy gate for forwarding to upstream
        try:
            self.policy.check_active_send(req.method, req.scheme, req.host, req.port,
                                          req.path(), origin="manual")
        except PermissionError as e:
            self.log(f"POLICY: {e}")
            return HttpResponse(status=403, reason="Forbidden",
                                headers=HeaderList([("Content-Type", "text/plain")]),
                                body=str(e).encode())
        if not self.policy.wait_rate(timeout=10):
            return HttpResponse(status=503, reason="Rate limited",
                                headers=HeaderList([("Content-Type", "text/plain")]),
                                body=b"OWSI rate limit exceeded")

        resp = send_request(req, timeout=self.policy.limits.timeout_sec,
                            max_response_size=self.policy.limits.max_response_size,
                            strip_hop_by_hop=True)

        dropped, rlogs = self.rules.apply("response", resp)
        for l in rlogs:
            self.log(l)
        if dropped:
            self.record(req, resp, extra_tags=["rule-drop-resp"])
            return HttpResponse(status=508, reason="Dropped by rule",
                                headers=HeaderList([("Content-Type", "text/plain")]),
                                body=b"Response dropped by OWSI rule")

        action, final_resp = self.interceptor.intercept_response(req, resp)
        if action == "drop":
            self.record(req, resp, extra_tags=["intercept-drop-resp"])
            return HttpResponse(status=508, reason="Dropped at intercept",
                                headers=HeaderList([("Content-Type", "text/plain")]),
                                body=b"Response dropped at OWSI intercept")
        resp = final_resp or resp

        self.record(req, resp)
        return resp

    # ------------------------------------------------------------------
    def record(self, req: HttpRequest, resp: HttpResponse,
               extra_tags: Optional[list] = None) -> None:
        from .analysis import detect_technologies, passive_analyze
        tech = ", ".join(detect_technologies(req, resp))
        entry = self.db.add_history(req, resp, tech=tech)
        findings = []
        if resp.status:
            findings = passive_analyze(req, resp, tls=req.scheme == "https")
        new_findings = []
        for f in findings:
            if not self.db.finding_exists(f["id"]):
                self.db.add_finding(f)
                new_findings.append(f)
        tags = list(extra_tags or [])
        if new_findings:
            worst = min(new_findings,
                        key=lambda f: {"high": 0, "medium": 1, "low": 2,
                                       "information": 3}[f["severity"]])
            tags.append(worst["severity"])
            self.db.update_history_meta(req.id, tags=tags)
        payload = {"entry": {k: v for k, v in entry.items()
                             if k not in ("request_raw", "response_raw")},
                   "findings": new_findings[:10], "tech": tech}
        self.bus.publish("history.new", payload)
        for nf in new_findings:
            self.bus.publish("finding.new", nf)

    # ------------------------------------------------------------------
    def tunnel(self, client, upstream) -> None:
        """Blind bidirectional copy for non-intercepted CONNECT tunnels."""
        socks = [client, upstream]
        try:
            while True:
                r, _, x = select.select(socks, [], socks, 30)
                if x:
                    break
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    other = upstream if s is client else client
                    other.sendall(data)
        except OSError:
            pass

    # ------------------------------------------------------------------
    def handle_websocket_upgrade(self, client_sock, req: HttpRequest) -> None:
        self.app.ws_engine.relay(client_sock, req)
