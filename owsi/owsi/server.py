"""OWSI control server: REST API + WebSocket event feed on 127.0.0.1:9000.

Consumers: apps/dashboard.html (the web UI) and the OWSI browser extension.
Serves the static app files too, so `owsi serve` alone gives you everything.
Pure stdlib http.server — no framework dependency.
"""
from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import os
import socketserver
import struct
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler

from . import __version__
from .analysis import (DECODER_OPS, analyze_cookies, analyze_jwt, compare,
                       decode, detect_technologies)
from .http_model import HttpRequest
from .report import build_report

APP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "apps")

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    app = None            # bound via subclass factory

    # ------------------------------------------------------------------ util
    def log_message(self, fmt, *args):       # silence default spam
        pass

    def _json(self, obj, code=200):
        blob = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(blob)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(blob)

    def _err(self, msg, code=400):
        self._json({"error": msg}, code)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _check_ext_token(self) -> bool:
        """Extension endpoints require the shared token issued at /ext/register
        (spec §71). Requests without X-OWSI-Token are rejected with 401."""
        import hmac
        tok = self.headers.get("X-OWSI-Token") or ""
        return bool(tok) and hmac.compare_digest(tok, self.app.ext_token)

    # ------------------------------------------------------------------ routes
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        p = u.path
        app = self.app
        try:
            if p == "/ws":
                return self._handle_ws_upgrade()
            if p == "/" or p == "/index.html":
                return self._static("dashboard.html")
            if p.startswith("/apps/"):
                return self._static(p[len("/apps/"):])
            if p == "/api/version":
                return self._json({"name": "OMEGA Web Security Interceptor",
                                   "product": "OWSI", "version": __version__,
                                   "uptimeSec": round(time.time() - app.started)})
            # ---------------- imports (spec 28-30) -----------------------
            if p == "/api/import/curl":
                from .imports import parse_curl
                req = parse_curl(q.get("cmd", ""))
                return self._json(req.summary())
            if p == "/api/import/har":
                from .imports import import_har
                raw = app.db.kv_get("_har_upload")
                if not raw:
                    return self._err("POST the HAR file to /api/import/har first",
                                     400)
                res = import_har(app, json.loads(raw))
                app.db.kv_set("_har_upload", None)
                return self._json(res)
            if p == "/api/import/openapi":
                from .imports import import_openapi
                raw = app.db.kv_get("_openapi_upload")
                if not raw:
                    return self._err("POST the OpenAPI spec to "
                                     "/api/import/openapi first", 400)
                res = import_openapi(app, json.loads(raw))
                app.db.kv_set("_openapi_upload", None)
                return self._json(res)
            if p == "/api/export/har":
                from .exports import export_har
                blob = json.dumps(export_har(app)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Disposition",
                                 "attachment; filename=owsi-export.har")
                self.send_header("Content-Length", str(len(blob)))
                self.end_headers()
                return self.wfile.write(blob)
            if p.startswith("/api/export/request/"):
                from .exports import export_formats
                e = app.db.get_history_entry(p.rsplit("/", 1)[1])
                if not e:
                    return self._err("not found", 404)
                req = app.db.history_request(e["id"])
                fmt = q.get("format", "curl")
                return self._json({"format": fmt,
                                   "text": export_formats(req).get(fmt, "")})
            if p.startswith("/api/graphql/") or p == "/api/graphql/detect":
                pass  # handled below via request analysis endpoints
            if p == "/api/status":
                return self._json({
                    "proxy": app.proxy.stats,
                    "policy": app.policy.to_dict(),
                    "intercept": {"interceptRequests": app.interceptor.intercept_requests,
                                  "interceptResponses": app.interceptor.intercept_responses,
                                  "pending": len(app.interceptor.pending())},
                    "historyCount": app.db.count_history(),
                    "findingsCount": len(app.db.list_findings()),
                    "ca": {"certPath": app.ca.ca_cert_path,
                           "fingerprint": app.ca.fingerprint_sha256},
                    "ai": app.ai.status(),
                })
            if p == "/api/history":
                return self._json({"entries": app.db.list_history(
                    limit=int(q.get("limit", 300)),
                    offset=int(q.get("offset", 0)),
                    host=q.get("host", ""), search=q.get("q", ""))})
            m = None
            if p.startswith("/api/history/"):
                e = app.db.get_history_entry(p.rsplit("/", 1)[1])
                return self._json(e) if e else self._err("not found", 404)
            if p == "/api/sitemap":
                return self._json({"nodes": app.db.sitemap()})
            if p == "/api/findings":
                return self._json({"findings": app.db.list_findings()})
            if p == "/api/intercept":
                return self._json(app.interceptor.state())
            if p == "/api/policy":
                return self._json(app.policy.to_dict())
            if p == "/api/rules":
                return self._json({"rules": app.rules.rules})
            if p == "/api/repeater/tabs":
                return self._json({"tabs": list(app.repeater.tabs.values())})
            if p == "/api/ws/sessions":
                return self._json({"sessions": app.ws_engine.list_sessions()})
            if p.startswith("/api/ws/frames/"):
                sid = p.rsplit("/", 1)[1]
                return self._json({"frames": app.db.ws_frames(sid)})
            if p == "/api/jobs":
                jobs = [app.fuzzer.job_state(j) for j in app.fuzzer.jobs.values()]
                scans = list(app.scanner.scans.values())
                return self._json({"fuzzJobs": jobs, "scans": scans})
            if p.startswith("/api/scan/"):
                st = app.scanner.scan_state(p.rsplit("/", 1)[1])
                return self._json(st) if st else self._err("no such scan", 404)
            if p.startswith("/api/fuzz/"):
                j = app.fuzzer.jobs.get(p.rsplit("/", 1)[1])
                return self._json(app.fuzzer.job_state(j)) if j \
                    else self._err("no such job", 404)
            if p == "/api/repeater/tabs":
                return self._json({"tabs": list(app.repeater.tabs.values())})
            if p == "/api/report":
                hosts = [h for h in q.get("hosts", "").split(",") if h]
                rep = build_report(app, scope_hosts=hosts or None,
                                     redact_secrets=q.get("redact", "0") in ("1","true"))
                fmt = q.get("format", "json")
                if fmt == "md":
                    blob = rep["markdown"].encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/markdown")
                    self.send_header("Content-Disposition",
                                     "attachment; filename=owsi-report.md")
                    self.send_header("Content-Length", str(len(blob)))
                    self.end_headers()
                    return self.wfile.write(blob)
                if fmt == "html":
                    blob = rep["html"].encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(blob)))
                    self.end_headers()
                    return self.wfile.write(blob)
                return self._json(rep)
            if p == "/api/ca":
                with open(app.ca.ca_cert_path, "rb") as f:
                    pem = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pem-file")
                self.send_header("Content-Disposition",
                                 "attachment; filename=owsi-ca-cert.pem")
                self.send_header("Content-Length", str(len(pem)))
                self.end_headers()
                return self.wfile.write(pem)
            if p == "/api/ai/proposals":
                return self._json({"proposals": list(app.ai.proposals.values())})
            if p == "/api/ai/history":
                return self._json({"messages": app.db.ai_history(
                    q.get("conv", "default"))})
            if p == "/api/analyzer/run":
                # re-run passive analyzer over stored history
                from .analysis import passive_analyze
                added = 0
                for e in app.db.list_history(limit=500):
                    req = app.db.history_request(e["id"])
                    ent = app.db.get_history_entry(e["id"])
                    if not req or not ent or not ent["response_raw"]:
                        continue
                    resp = HttpRequest  # placeholder to satisfy linters
                    from .http_model import HttpResponse
                    resp = HttpResponse.parse(bytes(ent["response_raw"]))
                    for fnd in passive_analyze(req, resp,
                                               tls=req.scheme == "https"):
                        if not app.db.finding_exists(fnd["id"]):
                            app.db.add_finding(fnd)
                            app.bus.publish("finding.new", fnd)
                            added += 1
                return self._json({"added": added})
            return self._err("unknown endpoint", 404)
        except PermissionError as e:
            return self._err(str(e), 403)
        except Exception as e:
            traceback.print_exc()
            return self._err(f"{type(e).__name__}: {e}", 500)

    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        p = u.path
        app = self.app
        d = self._body()
        try:
            if p == "/api/proxy/start":
                host = d.get("host", "127.0.0.1")
                port = int(d.get("port", 8080))
                try:
                    app.proxy.start((host, port))
                except OSError as e:
                    if "Address already in use" in str(e):
                        return self._err(f"port {port} already in use", 409)
                    raise
                return self._json({"ok": True, "listen": [host, port]})
            if p == "/api/proxy/stop":
                app.proxy.stop()
                return self._json({"ok": True})
            if p == "/api/proxy/https-intercept":
                app.proxy._engine.intercept_https = bool(d.get("enabled", True))
                return self._json({"ok": True,
                                   "enabled": app.proxy._engine.intercept_https})
            if p == "/api/intercept/config":
                app.interceptor.set_flags(d.get("requests"), d.get("responses"),
                                          d.get("timeoutSec"))
                return self._json(app.interceptor.state())
            if p == "/api/intercept/action":
                ok = app.interceptor.resolve(d.get("id", ""), d.get("action", "forward"),
                                             d.get("raw", ""))
                return self._json({"ok": ok}) if ok else self._err("stale id", 409)
            if p == "/api/policy":
                app.policy.update(d)
                app.db.kv_set("policy_state", app.policy.to_dict())
                app.db.kv_set("policy_mode", app.policy.mode)
                return self._json(app.policy.to_dict())
            if p == "/api/rules":
                app.rules.rules = d.get("rules", [])
                app.db.kv_set("rules", app.rules.rules)
                return self._json({"rules": app.rules.rules})
            if p == "/api/rules/test":
                # dry-run a rule matcher against one captured exchange —
                # no network, pure local evaluation (rule-builder preview)
                e = app.db.get_history_entry(d.get("id", ""))
                if not e:
                    return self._err("history entry not found", 404)
                req = app.db.history_request(e["id"])
                match = app.rules._matches(d.get("match", {}), req) \
                    if req is not None else False
                return self._json({"matches": match, "request": e["url"]})
            if p == "/api/history/meta":
                app.db.update_history_meta(d.get("id", ""), tags=d.get("tags"),
                                           note=d.get("note"),
                                           comment=d.get("comment"))
                return self._json({"ok": True})
            if p == "/api/history/delete":
                n = app.db.delete_history(ids=d.get("ids"), all_=bool(d.get("all")))
                return self._json({"deleted": n})
            if p == "/api/findings":
                f = app.db.add_finding(d)
                app.bus.publish("finding.new", f)
                return self._json(f)
            if p.startswith("/api/findings/") and p.endswith("/status"):
                fid = p.split("/")[3]
                ok = app.db.set_finding_status(fid, d.get("status", "open"))
                return self._json({"ok": ok})
            if p == "/api/repeater/send":
                ctx = d.get("context", {})
                req = HttpRequest.parse(d.get("requestRaw", "").encode("iso-8859-1"),
                                        default_scheme=ctx.get("scheme", "http"),
                                        default_host=ctx.get("host", ""),
                                        default_port=ctx.get("port", 80))
                resp = app.repeater.send(req, tab_id=d.get("tabId", ""))
                return self._json({"response": resp.summary(),
                                   "raw": resp.raw().decode("utf-8", "replace"),
                                   "requestRaw": req.raw().decode("utf-8", "replace")})
            if p == "/api/repeater/tab":
                return self._json(app.repeater.new_tab(d.get("name", "")))
            if p == "/api/fuzz/start":
                jid = app.fuzzer.start(d)     # the click itself is the approval…
                app.policy.approve_action(jid)  # …granted before any send happens
                return self._json({"jobId": jid})
            if p == "/api/fuzz/stop":
                return self._json({"ok": app.fuzzer.stop(d.get("jobId", ""))})
            if p == "/api/scan/start":
                sid = app.scanner.start_scan(d)
                return self._json({"scanId": sid})
            if p == "/api/decoder":
                try:
                    out = decode(d.get("op", ""), d.get("data", ""))
                    return self._json({"result": out})
                except Exception as e:
                    return self._err(f"decode failed: {e}")
            if p == "/api/compare":
                return self._json(compare(d.get("a", ""), d.get("b", "")))
            if p == "/api/jwt/analyze":
                return self._json(analyze_jwt(d.get("token", "")))
            if p == "/api/tech/detect":
                req = HttpRequest.parse(d.get("requestRaw", "").encode("latin1"))
                from .http_model import HttpResponse
                resp = HttpResponse.parse(d.get("responseRaw", "").encode("latin1")) \
                    if d.get("responseRaw") else None
                return self._json({"technologies": detect_technologies(req, resp)})
            if p == "/api/cookies/analyze":
                req = HttpRequest.parse(d.get("requestRaw", "").encode("latin1"))
                from .http_model import HttpResponse
                resp = HttpResponse.parse(d.get("responseRaw", "").encode("latin1"))
                return self._json({"cookies": analyze_cookies(req, resp)})
            if p == "/api/ai/analyze":
                r = app.ai.analyze(d.get("question", ""),
                                   d.get("historyIds", []),
                                   d.get("conv", "default"))
                return self._json(r)
            if p == "/api/ai/settings":
                app.ai.save_settings(d)
                return self._json(app.ai.status())
            if p == "/api/ai/proposal":
                r = app.ai.execute_proposal(d.get("id", ""),
                                            bool(d.get("approve", False)))
                return self._json(r)
            # ---------------- extension control API (spec 87–95) ----------
            if p == "/ext/register":
                app.db.kv_set("ext_client", {**d, "t": time.time()})
                app.bus.publish("ext.registered", d)
                return self._json({"ok": True, "version": __version__,
                                   "token": app.ext_token})
            if p in ("/ext/traffic", "/ext/command-result"):
                if not self._check_ext_token():
                    return self._err("missing or invalid X-OWSI-Token", 401)
            if p == "/ext/traffic":
                # extension forwards browser network events → history
                url = d.get("url", "")
                sp = urllib.parse.urlsplit(url)
                req = HttpRequest(method=d.get("method", "GET"),
                                  target=(sp.path or "/") +
                                  (("?" + sp.query) if sp.query else ""),
                                  scheme=sp.scheme or "http",
                                  host=sp.hostname or "",
                                  port=sp.port or (443 if sp.scheme == "https" else 80))
                req.source = "extension"
                req.comment = f"browser tab {d.get('tabId','')}"
                for k, v in (d.get("requestHeaders") or {}).items():
                    req.headers.add(k, str(v))
                resp = None
                from .http_model import HttpResponse
                resp = HttpResponse(status=int(d.get("statusCode") or 0),
                                    reason=d.get("statusLine", "").split(" ", 2)[-1],
                                    elapsed_ms=float(d.get("timeMs") or 0))
                for k, v in (d.get("responseHeaders") or {}).items():
                    resp.headers.add(k, str(v))
                if d.get("responseBodyPreview"):
                    resp.body = d["responseBodyPreview"].encode()
                entry = app.db.add_history(req, resp,
                                           tech=", ".join(
                                               detect_technologies(req, resp)))
                app.bus.publish("history.new", {"entry": {
                    k: v for k, v in entry.items()
                    if k not in ("request_raw", "response_raw")}})
                return self._json({"ok": True, "id": entry["id"]})
            if p == "/ext/command-result":
                app.bus.publish("ext.result", d)
                return self._json({"ok": True})
            if p == "/api/browser/set-proxy":
                cmd = {"cmd": "setProxy", "host": d.get("host", "127.0.0.1"),
                       "port": d.get("port", 8080)}
                app.bus.publish("ext.command", cmd)
                return self._json({"ok": True, "queued": cmd})
            if p == "/api/browser/clear-proxy":
                app.bus.publish("ext.command", {"cmd": "clearProxy"})
                return self._json({"ok": True})
            if p == "/api/browser/reload":
                app.bus.publish("ext.command", {"cmd": "reloadAll"})
                return self._json({"ok": True})
            if p == "/api/ws/inject":
                ok = app.ws_engine.send_to_server(d.get("sessionId", ""),
                                                  d.get("text", ""))
                return self._json({"ok": ok})
            if p == "/api/ws/pause":
                ok = app.ws_engine.set_paused(d.get("sessionId", ""),
                                              bool(d.get("paused", True)))
                return self._json({"ok": ok})
            # ---------------- uploads / search / graphql (spec 27-30,57) --
            if p in ("/api/import/har/upload", "/api/import/openapi/upload"):
                key = ("_har_upload" if "har" in p else "_openapi_upload")
                body = d.get("content", "")
                try:
                    parsed = json.loads(body)
                except Exception as e:
                    return self._err(f"invalid JSON file: {e}")
                app.db.kv_set(key, body)
                return self._json({"ok": True, "entries": len(
                    parsed.get("log", {}).get("entries", [])
                    ) if "har" in p else len(parsed.get("paths", {}))})
            if p == "/api/export/har":
                from .exports import export_har
                return self._json(export_har(app))
            if p == "/api/search":
                res = app.db.search_all(d.get("q", ""),
                                        regex=bool(d.get("regex", False)),
                                        case_sensitive=bool(
                                            d.get("caseSensitive", False)))
                return self._json(res)
            if p == "/api/graphql/analyze":
                from .analysis import analyze_graphql
                req = HttpRequest.parse(
                    d.get("requestRaw", "").encode("latin1"))
                return self._json(analyze_graphql(req))
            return self._err("unknown endpoint", 404)
        except PermissionError as e:
            return self._err(str(e), 403)
        except ValueError as e:
            return self._err(str(e), 422)
        except Exception as e:
            traceback.print_exc()
            return self._err(f"{type(e).__name__}: {e}", 500)

    # ------------------------------------------------------------------ static
    def _static(self, rel: str):
        full = os.path.normpath(os.path.join(APP_DIR, rel))
        if not full.startswith(APP_DIR) or not os.path.isfile(full):
            return self._err("not found", 404)
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as f:
            blob = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    # ------------------------------------------------------------------ WS feed
    def _handle_ws_upgrade(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            return self._err("ws upgrade required")
        accept = base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        sock = self.connection
        app = self.app

        queue: list = []
        cond = threading.Condition()

        def on_event(env):
            with cond:
                queue.append(env)
                if len(queue) > 500:
                    del queue[:-500]
                cond.notify_all()

        unsub = app.bus.subscribe("*", on_event)
        # send recent backlog so late joiners see current state
        for env in app.bus.recent[-50:]:
            queue.append(env)
        try:
            while True:
                with cond:
                    while not queue:
                        cond.wait(2.0)
                    batch, queue[:] = queue[:], []
                for env in batch:
                    payload = json.dumps(env, default=str).encode()
                    hdr = bytearray([0x81])
                    ln = len(payload)
                    if ln < 126:
                        hdr.append(ln)
                    elif ln < 65536:
                        hdr.append(126); hdr += struct.pack("!H", ln)
                    else:
                        hdr.append(127); hdr += struct.pack("!Q", ln)
                    try:
                        sock.sendall(bytes(hdr) + payload)
                    except OSError:
                        return
                # non-blocking check for client close/ping
                sock.settimeout(0.01)
                try:
                    data = sock.recv(8)
                    if data and data[0] & 0x0F == 0x8:
                        return
                except socket.timeout:
                    pass
                except OSError:
                    return
                finally:
                    sock.settimeout(None)
        finally:
            unsub()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_handler(app):
    h = type("BoundHandler", (Handler,), {"app": app})
    return h


def serve_control(app, addr=("127.0.0.1", 9000)):
    srv = Server(addr, make_handler(app))
    t = threading.Thread(target=srv.serve_forever, daemon=True, name="owsi-api")
    t.start()
    app.log(f"control API + dashboard on http://{addr[0]}:{addr[1]}")
    return srv
