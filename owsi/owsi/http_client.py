"""Real low-level HTTP/1.1 client used by proxy forward path, Repeater & Fuzzer.

Supports: content-length bodies, chunked transfer encoding, gzip/deflate,
keep-alive connections (connection pool keyed by scheme/host/port), timeouts,
and full raw request/response capture for the UI editors.
"""
from __future__ import annotations

import socket
import ssl
import threading
import time
from typing import Dict, Optional, Tuple

from .http_model import CRLF, HeaderList, HttpRequest, HttpResponse, parse_headers

HOP_BY_HOP = {"connection", "proxy-connection", "keep-alive", "te",
              "trailer", "transfer-encoding", "upgrade", "proxy-authenticate",
              "proxy-authorization"}


class HttpError(Exception):
    pass


class ConnectionPool:
    def __init__(self):
        self._lock = threading.Lock()
        self._conns: Dict[Tuple[str, str, int], list] = {}

    def get(self, scheme: str, host: str, port: int, timeout: float):
        key = (scheme, host, port)
        with self._lock:
            stack = self._conns.get(key) or []
            while stack:
                s = stack.pop()
                try:
                    s.getpeername()
                    return s
                except Exception:
                    try:
                        s.close()
                    except Exception:
                        pass
        addr = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        family, type_, proto, canon, sa = addr[0]
        s = socket.socket(family, type_, proto)
        s.settimeout(timeout)
        s.connect(sa)
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False      # lab tool: don't hard-fail odd certs
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        return s

    def put(self, scheme: str, host: str, port: int, s: socket.socket) -> None:
        key = (scheme, host, port)
        with self._lock:
            self._conns.setdefault(key, []).append(s)

    def close_all(self) -> None:
        with self._lock:
            for stack in self._conns.values():
                for s in stack:
                    try:
                        s.close()
                    except Exception:
                        pass
            self._conns.clear()


_pool = ConnectionPool()


def _read_until(sock, delim: bytes, limit: int) -> bytes:
    buf = b""
    while delim not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise HttpError("connection closed while reading headers")
        buf += chunk
        if len(buf) > limit:
            raise HttpError("header block too large")
    head, _, rest = buf.partition(delim)
    return head + delim, rest


def _recv_exact(sock, n: int, prebuf: bytes) -> Tuple[bytes, bytes]:
    data = prebuf
    while len(data) < n:
        chunk = sock.recv(min(65536, n - len(data)))
        if not chunk:
            break
        data += chunk
    return data[:n], data[n:]


def send_request(req: HttpRequest, *, timeout: Optional[float] = None,
                 max_response_size: int = 32 * 1024 * 1024,
                 strip_hop_by_hop: bool = False) -> HttpResponse:
    """Send a real request and return a fully parsed response."""
    timeout = timeout or 20.0
    host, port, scheme = req.host, req.port, req.scheme
    if not host:
        sp_host = req.hostname
        host = sp_host
        port = port or (443 if scheme == "https" else 80)
    out_headers = HeaderList(req.headers.items())
    if strip_hop_by_hop:
        for h in list(out_headers.names()):
            if h.lower() in HOP_BY_HOP:
                out_headers.remove(h)
    if "Host" not in out_headers:
        netloc = host if port in (80, 443) else f"{host}:{port}"
        out_headers.set("Host", netloc)
    wire = HttpRequest(method=req.method, target=req.target, version="HTTP/1.1",
                       headers=out_headers, body=req.body)
    raw = wire.raw()

    t0 = time.monotonic()
    s = None
    keep_ok = True
    try:
        s = _pool.get(scheme, host, port, timeout)
        s.sendall(raw)
        head, rest = _read_until(s, CRLF, 65536)
        status_line = head.split(CRLF)[0].decode("iso-8859-1")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise HttpError(f"bad status line: {status_line!r}")
        status = int(parts[1])
        reason = parts[2] if len(parts) > 2 else ""
        hdr_blob = head.split(CRLF, 1)[1]
        # headers may already include terminator
        while not hdr_blob.endswith(CRLF + CRLF):
            more = s.recv(65536)
            if not more:
                raise HttpError("connection closed while reading headers")
            hdr_blob += more
            if len(hdr_blob) > 262144:
                raise HttpError("header block too large")
        headers, consumed = parse_headers(hdr_blob)
        body_buf = rest + hdr_blob[consumed:]

        body = b""
        te = (headers.get("Transfer-Encoding") or "").lower()
        cl = headers.get("Content-Length")
        if "chunked" in te:
            while True:
                if CRLF not in body_buf:
                    line_more, body_buf = _read_until(s, CRLF, max_response_size)
                    size_tok = line_more.strip()
                else:
                    size_tok, _, body_buf = body_buf.partition(CRLF)
                try:
                    sz = int(size_tok.split(b";")[0], 16)
                except ValueError:
                    raise HttpError("bad chunk size")
                if sz == 0:
                    break
                while len(body_buf) < sz + 2:
                    chunk = s.recv(max(65536, sz + 2 - len(body_buf)))
                    if not chunk:
                        raise HttpError("truncated chunked body")
                    body_buf += chunk
                    if len(body_buf) > max_response_size:
                        raise HttpError("response exceeds max size")
                body += body_buf[:sz]
                body_buf = body_buf[sz + 2:]
                if len(body) > max_response_size:
                    raise HttpError("response exceeds max size")
        elif cl is not None and cl.isdigit():
            want = int(cl)
            while len(body_buf) < want:
                chunk = s.recv(min(65536, want - len(body_buf)))
                if not chunk:
                    break
                body_buf += chunk
                if len(body_buf) > max_response_size:
                    raise HttpError("response exceeds max size")
            body, body_buf = body_buf[:want], body_buf[want:]
        elif status not in (204, 304) and req.method != "HEAD":
            # read until EOF
            try:
                while len(body_buf) < max_response_size:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    body_buf += chunk
                body = body_buf
            finally:
                keep_ok = False
        if req.method == "HEAD" or status in (204, 304):
            keep_ok = cl is not None or "chunked" in te
        conn_hdr = (headers.get("Connection") or "").lower()
        if "close" in conn_hdr:
            keep_ok = False
        elapsed = (time.monotonic() - t0) * 1000.0
        resp = HttpResponse(status=status, reason=reason, version=parts[0],
                            headers=headers, body=body, elapsed_ms=elapsed)
        if keep_ok:
            s.settimeout(timeout)
            _pool.put(scheme, host, port, s)
            s = None
        return resp
    except Exception as e:
        elapsed = (time.monotonic() - t0) * 1000.0
        try:
            if s is not None:
                s.close()
        except Exception:
            pass
        return HttpResponse(status=0, reason="", elapsed_ms=elapsed,
                            error=f"{type(e).__name__}: {e}")
    finally:
        if s is not None and not keep_ok:
            try:
                s.close()
            except Exception:
                pass
