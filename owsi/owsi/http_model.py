"""HTTP message model for OWSI: real parsing/serialization, no mocks.

Everything is byte-oriented (raw wire format preserved) with a case-insensitive
header layer and helpers used across proxy, repeater, fuzzer, decoder, AI.
"""
from __future__ import annotations

import gzip
import io
import json
import re
import time
import uuid
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


def new_id() -> str:
    return uuid.uuid4().hex[:12]


class HeaderList:
    """Ordered, case-insensitive multi-value header collection."""

    def __init__(self, items: Optional[List[Tuple[str, str]]] = None):
        self._items: List[Tuple[str, str]] = list(items or [])

    # --- access ---------------------------------------------------------
    def get_all(self, name: str) -> List[str]:
        ln = name.lower()
        return [v for k, v in self._items if k.lower() == ln]

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        vals = self.get_all(name)
        return vals[0] if vals else default

    def __contains__(self, name: str) -> bool:
        return bool(self.get_all(name))

    def items(self) -> List[Tuple[str, str]]:
        return list(self._items)

    def names(self) -> List[str]:
        return [k for k, _ in self._items]

    # --- mutation -------------------------------------------------------
    def set(self, name: str, value: str) -> None:
        self.remove(name)
        self._items.append((name, value))

    def add(self, name: str, value: str) -> None:
        self._items.append((name, value))

    def remove(self, name: str) -> None:
        ln = name.lower()
        self._items = [(k, v) for k, v in self._items if k.lower() != ln]

    def to_dict(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for k, v in self._items:
            if k in out:
                out[k] += ", " + v
            else:
                out[k] = v
        return out


CRLF = b"\r\n"


def parse_headers(blob: bytes) -> Tuple[HeaderList, int]:
    """Parse headers up to terminating CRLFCRLF. Returns (headers, consumed)."""
    idx = blob.find(CRLF + CRLF)
    if idx < 0:
        return HeaderList(), 0
    block = blob[:idx].decode("iso-8859-1")
    headers = HeaderList()
    lines = block.split("\r\n")
    # do not skip the first line: when parsing a header block that follows a
    # request/status line, the caller already stripped that line.
    for line in lines:
        m = re.match(r"^([^:\r\n]+):\s*(.*)$", line)
        if m:
            headers.add(m.group(1).strip(), m.group(2))
        elif line.strip():
            # obs-fold continuation; append to previous
            if headers._items:
                k, v = headers._items[-1]
                headers._items[-1] = (k, v + " " + line.strip())
    return headers, idx + 4


@dataclass
class HttpRequest:
    method: str = "GET"
    target: str = "/"                     # origin-form path?query, or absolute URI
    version: str = "HTTP/1.1"
    headers: HeaderList = field(default_factory=HeaderList)
    body: bytes = b""
    # context filled by the proxy / sender
    scheme: str = "http"
    host: str = ""
    port: int = 80
    timestamp: float = field(default_factory=time.time)
    id: str = field(default_factory=new_id)
    source: str = "manual"                # proxy | repeater | fuzzer | extension | import
    comment: str = ""

    # ------------------------------------------------------------------
    @property
    def hostname(self) -> str:
        h = self.headers.get("Host") or self.host
        return h.split(":")[0].lower() if h else ""

    def url(self) -> str:
        parts = urlsplit(self.target if "://" in self.target
                         else f"{self.scheme}://{self.host}:{self.port}{self.target}")
        netloc = parts.netloc
        default_port = (parts.scheme == "http" and parts.port == 80) or \
                       (parts.scheme == "https" and parts.port == 443)
        if default_port:
            netloc = parts.hostname or ""
        return urlunsplit((parts.scheme or self.scheme, netloc,
                           parts.path or "/", parts.query, ""))

    def path(self) -> str:
        return urlsplit(self.target).path or "/"

    def query(self) -> str:
        return urlsplit(self.target).query

    def params(self) -> List[Tuple[str, str]]:
        p = list(parse_qsl(urlsplit(self.target).query, keep_blank_values=True))
        ct = (self.headers.get("Content-Type") or "").lower()
        if "urlencoded" in ct and self.body:
            try:
                p += parse_qsl(self.body.decode("utf-8", "replace"), keep_blank_values=True)
            except Exception:
                pass
        return p

    def param_locations(self) -> List[Tuple[str, str]]:
        """All injectable parameter locations: (name, location)."""
        locs: List[Tuple[str, str]] = [(k, "query") for k, _ in
                                       parse_qsl(urlsplit(self.target).query,
                                                 keep_blank_values=True)]
        ct = (self.headers.get("Content-Type") or "").lower()
        if "urlencoded" in ct and self.body:
            locs += [(k, "body") for k, _ in
                     parse_qsl(self.body.decode("utf-8", "replace"), keep_blank_values=True)]
        if ("json" in ct or self.body[:1] in (b"{", b"[")) and self.body:
            try:
                obj = json.loads(self.body.decode("utf-8"))
                locs += [(k, "json") for k in _flat_json_keys(obj)]
            except Exception:
                pass
        for name in self.headers.names():
            if name.lower() not in ("cookie",):
                continue
            for ck in self.headers.get_all("Cookie"):
                for pair in ck.split(";"):
                    if "=" in pair:
                        locs.append((pair.split("=", 1)[0].strip(), "cookie"))
        return locs

    def with_param(self, name: str, value: str, location: str) -> "HttpRequest":
        """Return a clone with one parameter replaced (used by the fuzzer)."""
        req = self.clone()
        if location == "query":
            sp = urlsplit(req.target)
            pairs = parse_qsl(sp.query, keep_blank_values=True)
            pairs = [(n, value) if n == name else (n, v) for n, v in pairs]
            req.target = urlunsplit((sp.scheme, sp.netloc, sp.path,
                                     urlencode(pairs), sp.fragment))
        elif location == "body":
            pairs = parse_qsl(req.body.decode("utf-8"), keep_blank_values=True)
            pairs = [(n, value) if n == name else (n, v) for n, v in pairs]
            req.set_body(urlencode(pairs).encode())
        elif location == "json":
            try:
                obj = json.loads(req.body.decode("utf-8"))
                _json_set(obj, name, value)
                req.set_body(json.dumps(obj).encode())
            except Exception:
                pass
        elif location == "cookie":
            cookies: Dict[str, str] = {}
            order: List[str] = []
            for ck in req.headers.get_all("Cookie"):
                for pair in ck.split(";"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        k = k.strip()
                        if k not in cookies:
                            order.append(k)
                        cookies[k] = v.strip()
            cookies[name] = value
            if name not in order:
                order.append(name)
            req.headers.set("Cookie", "; ".join(f"{k}={cookies[k]}" for k in order))
        return req

    def clone(self) -> "HttpRequest":
        r = HttpRequest(method=self.method, target=self.target, version=self.version,
                        headers=HeaderList(self.headers.items()), body=self.body,
                        scheme=self.scheme, host=self.host, port=self.port,
                        source=self.source, comment=self.comment)
        r.id = new_id()
        r.timestamp = time.time()
        return r

    # ------------------------------------------------------------------
    def set_body(self, body: bytes) -> None:
        self.body = body
        # keep Content-Length consistent whenever it exists or the message
        # carries a body (fuzzed/mutated requests must transmit correctly)
        if "Content-Length" in self.headers or body:
            self.headers.set("Content-Length", str(len(body)))

    def raw(self, origin_form: bool = True) -> bytes:
        target = self.target
        if not origin_form and "://" not in target:
            target = f"{self.scheme}://{self.host}:{self.port}{target}"
        out = f"{self.method} {target} {self.version}\r\n".encode("iso-8859-1")
        for k, v in self.headers.items():
            out += f"{k}: {v}\r\n".encode("iso-8859-1")
        return out + CRLF + self.body

    @classmethod
    def parse(cls, raw: bytes, *, default_scheme: str = "http",
              default_host: str = "", default_port: int = 80) -> "HttpRequest":
        head, _, rest = raw.partition(CRLF)
        parts = head.decode("iso-8859-1").split(" ")
        if len(parts) < 3:
            raise ValueError(f"bad request line: {head[:120]!r}")
        method, target, version = parts[0], parts[1], " ".join(parts[2:])
        headers, consumed = parse_headers(rest)
        body = rest[consumed:]
        host_hdr = headers.get("Host") or default_host
        host_only, port = host_hdr, default_port
        if ":" in host_hdr and not host_hdr.startswith("["):
            host_only, p = host_hdr.rsplit(":", 1)
            try:
                port = int(p)
            except ValueError:
                pass
        req = cls(method=method, target=target, version=version, headers=headers,
                  body=body, host=host_only, port=port)
        # keep .host authoritative even when only a Host header was supplied
        if not req.host and host_hdr:
            req.host = host_hdr.split(":")[0] if not host_hdr.startswith("[") else host_hdr
        if "://" in target:
            # absolute-URI form (proxied requests): normalize to origin-form
            sp = urlsplit(target)
            req.scheme = sp.scheme
            if sp.hostname:
                req.host = sp.hostname
                req.port = sp.port or (443 if sp.scheme == "https" else 80)
                if not req.headers.get("Host"):
                    hostval = sp.hostname
                    if req.port not in (80, 443):
                        hostval += f":{req.port}"
                    req.headers.set("Host", hostval)
            req.target = urlunsplit(("", "", sp.path or "/", sp.query, sp.fragment))
        else:
            req.scheme = default_scheme
        return req

    def summary(self) -> dict:
        return {
            "id": self.id, "method": self.method, "url": self.url(),
            "host": self.hostname, "path": self.path(), "scheme": self.scheme,
            "port": self.port, "timestamp": self.timestamp, "source": self.source,
            "size": len(self.body), "comment": self.comment,
        }


def _flat_json_keys(obj, prefix="") -> List[str]:
    keys: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                keys.extend(_flat_json_keys(v, path))
            else:
                keys.append(path)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, (dict, list)):
                keys.extend(_flat_json_keys(v, f"{prefix}[{i}]"))
    return keys


def _json_set(obj, dotted: str, value: str) -> None:
    parts = re.split(r"\.|\[(\d+)\]", dotted.replace("[]", "[0]"))
    parts = [p for p in parts if p not in (None, "")]
    cur = obj
    for p in parts[:-1]:
        cur = cur[int(p)] if isinstance(cur, list) else cur[p]
    last = parts[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value


@dataclass
class HttpResponse:
    status: int = 200
    reason: str = "OK"
    version: str = "HTTP/1.1"
    headers: HeaderList = field(default_factory=HeaderList)
    body: bytes = b""
    elapsed_ms: float = 0.0
    error: str = ""

    def content_type(self) -> str:
        return (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()

    def decoded_body(self) -> bytes:
        enc = (self.headers.get("Content-Encoding") or "").lower().strip()
        try:
            if enc == "gzip":
                return gzip.decompress(self.body)
            if enc == "deflate":
                try:
                    return zlib.decompress(self.body)
                except zlib.error:
                    return zlib.decompress(self.body, -zlib.MAX_WBITS)
            if enc == "br":
                import brotli  # optional
                return brotli.decompress(self.body)
        except Exception:
            pass
        return self.body

    def text(self, limit: int = 200_000) -> str:
        b = self.decoded_body()[:limit]
        return b.decode("utf-8", "replace")

    def is_html(self) -> bool:
        return "html" in self.content_type()

    def json(self):
        try:
            return json.loads(self.decoded_body().decode("utf-8"))
        except Exception:
            return None

    def raw(self) -> bytes:
        out = f"{self.version} {self.status} {self.reason}\r\n".encode("iso-8859-1")
        for k, v in self.headers.items():
            out += f"{k}: {v}\r\n".encode("iso-8859-1")
        return out + CRLF + self.body

    @classmethod
    def parse(cls, raw: bytes) -> "HttpResponse":
        head, _, rest = raw.partition(CRLF)
        parts = head.decode("iso-8859-1").split(" ", 2)
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        reason = parts[2] if len(parts) > 2 else ""
        headers, consumed = parse_headers(rest)
        return cls(status=status, reason=reason, version=parts[0],
                   headers=headers, body=rest[consumed:])

    def summary(self) -> dict:
        return {
            "status": self.status, "reason": self.reason,
            "contentType": self.content_type(),
            "length": len(self.decoded_body()), "elapsedMs": round(self.elapsed_ms, 1),
            "error": self.error,
        }
