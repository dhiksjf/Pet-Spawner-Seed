"""Active modules: Repeater (spec 21), Intruder-style Fuzzer (spec 23),
Scanner-lite (spec 36), WebSocket relay engine (spec 26).

Every outbound send goes through the SecurityPolicy gate + rate limiter and
is recorded in history with its source tag.
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import struct
import threading
import time
import urllib.parse
import uuid
from typing import Callable, Dict, List, Optional

from .http_client import send_request
from .http_model import CRLF, HeaderList, HttpRequest, HttpResponse


# ===========================================================================
# Repeater
# ===========================================================================

class Repeater:
    def __init__(self, app):
        self.app = app
        self.tabs: Dict[str, dict] = {}      # workspace tabs (spec 22)

    def new_tab(self, name: str = "") -> dict:
        tid = uuid.uuid4().hex[:8]
        tab = {"id": tid, "name": name or f"Tab {len(self.tabs)+1}",
               "requestRaw": "", "responses": []}
        self.tabs[tid] = tab
        return tab

    def send(self, req: HttpRequest, *, tab_id: str = "", origin: str = "repeater") \
            -> HttpResponse:
        # "manual" only when the user themselves clicked send; automated
        # origins (ai-copilot, ...) must still satisfy the dangerous-action
        # approval gate in LAB/AUTHORIZED modes.
        gate_origin = "manual" if origin in ("repeater", "manual", "cli") else origin
        self.app.policy.check_active_send(
            req.method, req.scheme, req.host, req.port, req.path(),
            origin=gate_origin)
        if not self.app.policy.wait_rate(timeout=10):
            raise TimeoutError("rate limiter timeout")
        req.source = origin
        resp = send_request(req, timeout=self.app.policy.limits.timeout_sec,
                            max_response_size=self.app.policy.limits.max_response_size,
                            strip_hop_by_hop=True)
        self.app.proxy.record(req, resp, extra_tags=[origin])
        if tab_id and tab_id in self.tabs:
            t = self.tabs[tab_id]
            t["requestRaw"] = req.raw().decode("utf-8", "replace")
            t["responses"].append(resp.raw().decode("utf-8", "replace"))
            t["responses"] = t["responses"][-20:]
        self.app.bus.publish("repeater.sent", {"request": req.summary(),
                                               "response": resp.summary()})
        return resp


# ===========================================================================
# Fuzzer / Intruder (spec 23)
# ===========================================================================

class FuzzJob:
    def __init__(self, job_id: str, request: HttpRequest, positions: List[dict],
                 payload_set: List[str], mode: str = "sniper"):
        self.id = job_id
        self.request = request
        self.positions = positions          # [{name, location}]
        self.payloads = payload_set
        self.mode = mode                    # sniper | battering ram
        self.results: List[dict] = []
        self.total = 0
        self.done = 0
        self.status = "queued"              # queued|running|done|stopped|error
        self.stop_flag = threading.Event()
        self.started = time.time()
        self.baseline_length: Optional[int] = None


class Fuzzer:
    def __init__(self, app):
        self.app = app
        self.jobs: Dict[str, FuzzJob] = {}

    def build_payload_matrix(self, job: FuzzJob) -> List[tuple]:
        """Return list of (position, payload) work items."""
        items: List[tuple] = []
        if job.mode == "battering ram":
            for pos in job.positions:
                pass
            for payload in job.payloads:
                for pos in job.positions:
                    items.append((pos, payload))
        else:  # sniper: one position at a time
            for pos in job.positions:
                for payload in job.payloads:
                    items.append((pos, payload))
        return items

    def start(self, data: dict) -> str:
        raw = data.get("requestRaw", "").encode("iso-8859-1")
        ctx = data.get("context", {})
        req = HttpRequest.parse(raw, default_scheme=ctx.get("scheme", "http"),
                                default_host=ctx.get("host", ""),
                                default_port=ctx.get("port", 80))
        positions = data.get("positions") or [
            {"name": n, "location": l} for n, l in req.param_locations()]
        payloads = data.get("payloads") or []
        if not payloads:
            raise ValueError("no payloads supplied")
        job = FuzzJob(uuid.uuid4().hex[:8], req, positions, payloads,
                      data.get("mode", "sniper"))
        job.total = len(self.build_payload_matrix(job))
        self.jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True,
                         name=f"fuzz-{job.id}").start()
        return job.id

    def stop(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        if not job:
            return False
        job.stop_flag.set()
        return True

    def job_state(self, job: FuzzJob) -> dict:
        return {"id": job.id, "status": job.status, "mode": job.mode,
                "done": job.done, "total": job.total,
                "elapsedSec": round(time.time() - job.started, 1),
                "results": job.results[-200:],
                "positions": job.positions, "payloadCount": len(job.payloads)}

    # ------------------------------------------------------------------
    def _run(self, job: FuzzJob) -> None:
        pol = self.app.policy
        job.status = "running"
        lim = pol.limits
        try:
            # baseline (unmutated) response for anomaly comparison
            base = self._send_once(job.request, job)
            job.baseline_length = base.decoded_body().__len__() if base else None
            matrix = self.build_payload_matrix(job)
            sem = threading.Semaphore(lim.max_concurrency)
            lock = threading.Lock()

            def worker(pos, payload):
                if job.stop_flag.is_set():
                    return
                if time.time() - job.started > lim.max_job_duration_sec:
                    job.stop_flag.set()
                    return
                with lock:
                    if len(job.results) >= lim.max_requests_per_job:
                        return
                if not pol.wait_rate(timeout=15):
                    return
                mutated = job.request.with_param(pos["name"], payload,
                                                 pos["location"])
                resp = self._send_once(mutated, job,
                                       label=f"{pos['location']}:{pos['name']}={payload}")
                with lock:
                    job.done += 1
                self.app.bus.publish("fuzz.progress",
                                     {"jobId": job.id, "done": job.done,
                                      "total": job.total})

            threads: List[threading.Thread] = []
            for pos, payload in matrix:
                if job.stop_flag.is_set():
                    break
                sem.acquire()

                def run_one(p=pos, pl=payload):
                    try:
                        worker(p, pl)
                    finally:
                        sem.release()
                t = threading.Thread(target=run_one, daemon=True)
                t.start()
                threads.append(t)
                # throttle thread creation to concurrency window
                alive = sum(1 for th in threads if th.is_alive())
                while alive >= lim.max_concurrency and not job.stop_flag.is_set():
                    time.sleep(0.02)
                    alive = sum(1 for th in threads if th.is_alive())
            for t in threads:
                t.join(timeout=lim.timeout_sec + 5)
            job.status = "stopped" if job.stop_flag.is_set() else "done"
        except Exception as e:
            job.status = "error"
            job.results.append({"error": f"{type(e).__name__}: {e}"})
        self.app.bus.publish("fuzz.done", {"jobId": job.id, "status": job.status})

    def _send_once(self, req: HttpRequest, job: FuzzJob, label: str = "") \
            -> Optional[HttpResponse]:
        try:
            self.app.policy.check_active_send(req.method, req.scheme, req.host,
                                              req.port, req.path(), origin="fuzzer",
                                              action_id=job.id)
        except PermissionError as e:
            job.results.append({"url": req.url(), "error": str(e)})
            return None
        req.source = "fuzzer"
        req.comment = label
        resp = send_request(req, timeout=self.app.policy.limits.timeout_sec,
                            max_response_size=self.app.policy.limits.max_response_size,
                            strip_hop_by_hop=True)
        self.app.proxy.record(req, resp, extra_tags=["fuzzer"])
        body_len = len(resp.decoded_body())
        entry = {"url": req.url(), "label": label, "status": resp.status,
                 "length": body_len, "elapsedMs": round(resp.elapsed_ms, 1),
                 "error": resp.error}
        if job.baseline_length is not None and body_len:
            delta = body_len - job.baseline_length
            if abs(delta) > max(30, 0.1 * job.baseline_length):
                entry["anomaly"] = f"length delta {delta:+d} vs baseline"
        job.results.append(entry)
        return resp


# NOTE: automated jobs are approved via policy.approve_action(job_id) by the UI
# when the user clicks "Start attack" — that click IS the explicit approval.


# ===========================================================================
# Scanner-lite (spec 36): passive-first, active checks only in-scope+approved
# ===========================================================================

PAYLOAD_LIBRARY = {
    "xss": ["\"><svg/onload=alert(1)>", "'-alert(1)-'", "<img src=x onerror=alert(1)>"],
    "sqli": ["'", "\"", "1' OR '1'='1", "1; WAITFOR DELAY '0:0:2'--", "-1 UNION SELECT NULL--"],
    "traversal": ["../../etc/passwd", "..%2f..%2fetc%2fpasswd",
                  "....//....//etc/passwd"],
    "cmdinj": [";id", "|id", "`id`", ";cat /etc/passwd"],
}

SQLI_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation",
    "quoted string not properly terminated", "pg_query", "sqlite3::sqlexception",
    "ora-0", "sqlstate", "microsoft ole provider for sql server",
]
XSS_ECHO_MARK = "<owsi>xssprobe</owsi>"
TRAVERSAL_MARKERS = ["root:", "daemon:", "[fonts]", "bin/bash"]


class Scanner:
    def __init__(self, app):
        self.app = app
        self.scans: Dict[str, dict] = {}

    def start_scan(self, data: dict) -> str:
        sid = uuid.uuid4().hex[:8]
        targets = data.get("urls") or []
        categories = data.get("categories") or ["xss", "sqli", "traversal"]
        if not targets:
            # crawl sitemap hosts/paths within scope
            entries = self.app.db.list_history(limit=500)
            seen = set()
            for e in entries:
                u = e["url"]
                if u not in seen:
                    seen.add(u)
                    targets.append(u)
                if len(targets) >= int(data.get("maxUrls", 25)):
                    break
        scan = {"id": sid, "status": "running", "targets": targets[:80],
                "categories": categories, "findings": [], "tested": 0,
                "started": time.time()}
        self.scans[sid] = scan
        self.app.policy.approve_action(sid)   # clicking Start = approval token
        threading.Thread(target=self._run, args=(scan,), daemon=True,
                         name=f"scan-{sid}").start()
        return sid

    def scan_state(self, sid: str) -> Optional[dict]:
        s = self.scans.get(sid)
        if not s:
            return None
        return {k: v for k, v in s.items() if k != "targets"} | \
            {"total": len(s["targets"])}

    def _run(self, scan: dict) -> None:
        pol = self.app.policy
        try:
            for url in scan["targets"]:
                if scan["status"] != "running":
                    break
                try:
                    req = HttpRequest.parse(
                        f"GET {url} HTTP/1.1\r\nHost: {urllib.parse.urlsplit(url).netloc}"
                        f"\r\nUser-Agent: owsi-scanner\r\n\r\n".encode())
                    sp = urllib.parse.urlsplit(url)
                    req.scheme, req.host = sp.scheme, sp.hostname or ""
                    req.port = sp.port or (443 if sp.scheme == "https" else 80)
                    req.target = (sp.path or "/") + (("?" + sp.query) if sp.query else "")
                except Exception:
                    continue
                params = req.param_locations()
                cats = scan["categories"]
                for cat in cats:
                    for pos in (params or [{"name": None, "location": "path"}]):
                        for payload in PAYLOAD_LIBRARY.get(cat, [])[:2]:
                            if not pol.wait_rate(timeout=15):
                                continue
                            probe = self._make_probe(req, pos, payload, cat)
                            try:
                                pol.check_active_send(probe.method, probe.scheme,
                                                      probe.host, probe.port,
                                                      probe.path(), origin="scanner",
                                                      action_id=scan["id"])
                            except PermissionError:
                                scan["status"] = "blocked-by-policy"
                                return
                            resp = send_request(probe, timeout=pol.limits.timeout_sec,
                                                strip_hop_by_hop=True)
                            self.app.proxy.record(probe, resp, extra_tags=["scanner"])
                            scan["tested"] += 1
                            hit = self._check(cat, payload, probe, resp)
                            if hit:
                                fid = hashlib.sha1(
                                    f"{hit['title']}|{probe.url()}".encode()).hexdigest()[:16]
                                if not self.app.db.finding_exists(fid):
                                    hit["id"] = fid
                                    self.app.db.add_finding(hit)
                                    scan["findings"].append(hit)
                                    self.app.bus.publish("finding.new", hit)
                self.app.bus.publish("scan.progress",
                                     {"scanId": scan["id"],
                                      "tested": scan["tested"]})
            scan["status"] = "done"
        except Exception as e:
            scan["status"] = f"error: {e}"
        self.app.bus.publish("scan.done", {"scanId": scan["id"],
                                           "status": scan["status"],
                                           "findings": len(scan["findings"])})

    @staticmethod
    def _make_probe(req: HttpRequest, pos: dict, payload: str, cat: str) \
            -> HttpRequest:
        r = req.clone()
        if pos["location"] == "path" and pos["name"] is None:
            if cat == "traversal":
                r.target = urllib.parse.urljoin(r.target.rstrip("/") + "/", payload)
            else:
                q = r.query
                r.target = r.path() + "?" + ((q + "&" if q else "") +
                                             "owsitest=" +
                                             urllib.parse.quote(payload))
            return r
        enc = payload
        return r.with_param(pos["name"], enc, pos["location"])

    @staticmethod
    def _check(cat: str, payload: str, req: HttpRequest,
               resp: HttpResponse) -> Optional[dict]:
        if resp.status == 0:
            return None
        body = resp.text(120_000)
        low = body.lower()
        base = {"url": req.url(), "confidence": "firm", "status": "open",
                "source": "scanner", "severity": "high",
                "created": time.time(), "updated": time.time()}
        if cat == "sqli":
            for sig in SQLI_ERRORS:
                if sig in low:
                    return {**base, "title": "SQL injection (error-based)",
                            "description": "A SQL error signature appeared in the "
                            "response after injecting a SQL metacharacter payload.",
                            "evidence": f"payload={payload!r}; matched '{sig}'\n"
                                        f"--- excerpt ---\n{_excerpt(low, sig)}",
                            "recommendation": "Use parameterised queries; suppress "
                            "database errors."}
        elif cat == "xss":
            marker = payload.replace("<", "&lt;")
            if payload in body and resp.is_html():
                return {**base, "severity": "high",
                        "title": "Reflected XSS candidate (unescaped echo)",
                        "description": "The XSS probe payload was reflected into an "
                        "HTML response without encoding. Verify manually before "
                        "reporting.",
                        "evidence": f"payload={payload!r} reflected verbatim",
                        "recommendation": "Contextually encode output; CSP."}
        elif cat == "traversal":
            for m in TRAVERSAL_MARKERS:
                if m in low and resp.status == 200:
                    return {**base, "title": "Path traversal (file read)",
                            "description": "Traversal payload returned content that "
                            "matches known file signatures.",
                            "evidence": f"payload={payload!r}; matched {m!r}\n"
                                        f"--- excerpt ---\n{_excerpt(low, m)}",
                            "recommendation": "Canonicalise & sandbox file access."}
        elif cat == "cmdinj":
            if ("uid=" in low and resp.status == 200) or "daemon:" in low and \
                    payload.strip(";|` ").startswith("cat"):
                return {**base, "title": "OS command injection candidate",
                        "description": "Command output signature appeared after "
                        "injection payload.",
                        "evidence": f"payload={payload!r}",
                        "recommendation": "Avoid shell interpolation; validate input."}
        return None


def _excerpt(hay: str, needle: str, width: int = 160) -> str:
    i = hay.find(needle)
    if i < 0:
        return ""
    return hay[max(0, i - width // 2): i + width]


# ===========================================================================
# WebSocket relay engine (spec 26)
# ===========================================================================

class WSEngine:
    """Relays browser <-> server WS frames, logs both directions, supports
    inject-from-UI and pause (frames buffered while paused)."""

    OPCODES = {0x0: "continuation", 0x1: "text", 0x2: "binary",
               0x8: "close", 0x9: "ping", 0xA: "pong"}

    def __init__(self, app):
        self.app = app
        self.sessions: Dict[str, dict] = {}
        self.lock = threading.Lock()

    # ---- RFC6455 frame codec -----------------------------------------
    @staticmethod
    def _read_frame(sock) -> tuple[int, bytes, bytes]:
        hdr = WSEngine._recv_exact(sock, 2)
        b0, b1 = hdr[0], hdr[1]
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        ext = b""
        if length == 126:
            ext = WSEngine._recv_exact(sock, 2)
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = WSEngine._recv_exact(sock, 8)
            length = struct.unpack("!Q", ext)[0]
        mask_key = b""
        if masked:
            mask_key = WSEngine._recv_exact(sock, 4)
        payload = WSEngine._recv_exact(sock, length) if length else b""
        if masked and mask_key:
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        fin = b0 & 0x80
        return opcode, payload, hdr + ext + mask_key

    @staticmethod
    def _recv_exact(sock, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("ws closed")
            data += chunk
        return data

    @staticmethod
    def _encode_frame(opcode: int, payload: bytes, mask: bool = False) -> bytes:
        out = bytearray([0x80 | opcode])
        ln = len(payload)
        if ln < 126:
            out.append(0x80 | ln if mask else ln)
        elif ln < 65536:
            out.append(0x80 | 126 if mask else 126)
            out += struct.pack("!H", ln)
        else:
            out.append(0x80 | 127 if mask else 127)
            out += struct.pack("!Q", ln)
        if mask:
            key = uuid.uuid4().bytes[:4]
            out += key
            payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
        return bytes(out) + payload

    # ---- relay ----------------------------------------------------------
    def relay(self, client_sock: socket.socket, req: HttpRequest) -> None:
        """Called from proxy when browser sends WS Upgrade through us."""
        sp = urllib.parse.urlsplit(req.url().replace("http://", "ws://")
                                   .replace("https://", "wss://"))
        host = req.host
        port = req.port
        scheme = req.scheme
        sess_id = uuid.uuid4().hex[:8]
        try:
            up = self.app.ws_connect_upstream(scheme, host, port, req)
        except Exception as e:
            self.app.log(f"ws upstream connect failed: {e}")
            try:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except OSError:
                pass
            return
        # forward the original upgrade request upstream
        up.sendall(req.raw())
        # read upstream's handshake response
        resp_head = b""
        while CRLF + CRLF not in resp_head:
            more = up.recv(4096)
            if not more:
                self.app.log("ws upstream handshake failed")
                up.close()
                return
            resp_head += more
        client_sock.sendall(resp_head)
        status_line = resp_head.split(CRLF, 1)[0].decode("latin1")
        if "101" not in status_line:
            up.close()
            return
        session = {"id": sess_id, "url": req.url(), "paused": False,
                   "buffered": [], "started": time.time(),
                   "handshakeResp": status_line, "serverSock": up}
        with self.lock:
            self.sessions[sess_id] = session
        # persist the session so it survives relay close (history view)
        self.app.db.add_ws_session(sess_id, req.url(), status_line)
        self.app.bus.publish("ws.session", {"sessionId": sess_id,
                                            "url": req.url()})
        self.app.log(f"WebSocket session {sess_id} relay open → {req.url()}")

        def pump(src, dst, direction):
            try:
                while True:
                    opcode, payload, _raw = self._read_frame(src)
                    if session["paused"] and opcode in (0x1, 0x2):
                        # hold this frame (and any that arrive while paused)
                        # until resume; then replay the whole buffer in order.
                        with self.lock:
                            session["buffered"].append((direction, opcode, payload))
                            while session["paused"]:
                                self.lock.release()
                                time.sleep(0.1)
                                self.lock.acquire()
                            buf, session["buffered"] = session["buffered"], []
                        for d, op, pl in buf:
                            target = client_sock if d == "to-server" else up
                            target.sendall(self._encode_frame(op, pl,
                                                               mask=(d == "to-server")))
                            self._log_frame(sess_id, d, op, pl)
                        continue
                    dst_masked = self._encode_frame(opcode, payload,
                                                    mask=(direction == "to-server"))
                    dst.sendall(dst_masked)
                    self._log_frame(sess_id, direction, opcode, payload)
                    if opcode == 0x8:
                        break
            except (ConnectionError, OSError, ssl.SSLError):
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t1 = threading.Thread(target=pump, args=(client_sock, up, "to-server"),
                              daemon=True)
        t2 = threading.Thread(target=pump, args=(up, client_sock, "to-client"),
                              daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
        up.close()
        self.app.log(f"WebSocket session {sess_id} closed")

    def _log_frame(self, sess_id: str, direction: str, opcode: int,
                   payload: bytes) -> None:
        name = self.OPCODES.get(opcode, hex(opcode))
        self.app.db.add_ws_frame(sess_id, direction, name, payload)
        self.app.bus.publish("ws.frame", {
            "sessionId": sess_id, "direction": direction, "opcode": name,
            "preview": payload[:512].decode("utf-8", "replace"),
            "size": len(payload)})

    def send_to_server(self, sess_id: str, text: str) -> bool:
        """Inject a frame toward the server (used by UI 'Send Frame')."""
        sess = self.sessions.get(sess_id)
        if not sess:
            return False
        sess.setdefault("_inject_queue", []).append(text)
        # simplest reliable path: write directly via stored ref would need socket;
        # we attach sockets at relay start:
        sock = sess.get("serverSock")
        if sock:
            data = self._encode_frame(0x1, text.encode(), mask=False)
            sock.sendall(data)
            self._log_frame(sess_id, "injected-to-server", 0x1, text.encode())
            return True
        return False

    def set_paused(self, sess_id: str, paused: bool) -> bool:
        sess = self.sessions.get(sess_id)
        if not sess:
            return False
        sess["paused"] = paused
        return True

    def list_sessions(self) -> list:
        return [{"id": s["id"], "url": s["url"], "paused": s["paused"],
                 "started": s["started"]} for s in self.sessions.values()] \
            + self.app.db.list_ws_sessions()
