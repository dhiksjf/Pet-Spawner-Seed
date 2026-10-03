"""OWSI core — the single source of truth.

Application object wires: policy, DB, event bus, CA, proxy engine, interceptor,
rules, repeater, fuzzer, scanner, WS engine, AI copilot, report generator.

Also exposes the browser-extension control API (spec 14/87–95) over a
localhost HTTP+WebSocket server consumed by apps/dashboard.html and the
Chrome/Edge extension in apps/extension/.
"""
from __future__ import annotations

import json
import socket
import ssl
import threading
import time
import urllib.parse
from typing import Optional

from . import __version__
from .ai import AIEngine
from .analysis import RuleEngine
from .ca import CertificateAuthority
from .db import ProjectDB
from .events import EventBus
from .http_model import CRLF, HttpRequest, HttpResponse
from .intercept import Interceptor
from .modules import Fuzzer, Repeater, Scanner, WSEngine
from .policy import SecurityPolicy, TargetScope


class Application:
    def __init__(self, data_dir: str):
        import os
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.db = ProjectDB(os.path.join(data_dir, "owsi.db"))
        self.bus = EventBus()
        self.policy = SecurityPolicy(mode=self.db.kv_get("policy_mode", "LAB"))
        saved_scope = self.db.kv_get("policy_state")
        if saved_scope:
            self.policy.update(saved_scope)
        self.ca = CertificateAuthority(os.path.join(data_dir, "ca"))
        self.interceptor = Interceptor()
        self.rules = RuleEngine()
        saved_rules = self.db.kv_get("rules")
        if saved_rules:
            self.rules.rules = saved_rules
        self.repeater = Repeater(self)
        self.fuzzer = Fuzzer(self)
        self.scanner = Scanner(self)
        self.ws_engine = WSEngine(self)
        self.ai = AIEngine(self)                   # needs db/policy refs first
        self.proxy = ProxyEngineRef(self)          # late-bound real engine
        self.started = time.time()
        # shared secret issued to the browser extension at registration time
        # (spec §71 native-messaging / localhost IPC security)
        import secrets as _secrets
        self.ext_token = self.db.kv_get("ext_token") or \
            _secrets.token_hex(16)
        self.db.kv_set("ext_token", self.ext_token)

    # tiny shim so modules can call app.proxy.record before proxy start ------
    def log(self, msg: str) -> None:
        self.proxy.log(msg)


# Import after class defs to avoid cycle
from .proxy import ProxyEngine  # noqa: E402


class ProxyEngineRef:
    """Lazy wrapper: modules use app.proxy.*; the real ProxyEngine is created
    when the proxy subsystem first starts, but record()/log() work always.

    NOTE: attribute writes (e.g. ``app.proxy.intercept_https = False``) must
    reach the underlying engine — Python would otherwise set them on this
    wrapper object and silently shadow the real flag. __setattr__ fixes that.
    """

    def __init__(self, app: Application):
        self.app = app
        self._engine = ProxyEngine(app)

    def __getattr__(self, name):
        # only called for attributes not found on the wrapper itself
        return getattr(self._engine, name)

    def __setattr__(self, name, value):
        if name in ("app", "_engine"):
            object.__setattr__(self, name, value)
        else:
            setattr(self._engine, name, value)

    # --- convenience passthroughs used everywhere -----------------------
    def record(self, req, resp, extra_tags=None):
        self._engine.record(req, resp, extra_tags)

    def log(self, msg):
        self._engine.log(msg)

    def start(self, addr=("127.0.0.1", 8080)):
        self._engine.start(addr)

    def stop(self):
        self._engine.stop()

    @property
    def stats(self):
        e = self._engine
        return {"running": e._running, "listen": list(e.listen_addr),
                "requests": e.request_count,
                "interceptHttps": e.intercept_https,
                "log": e.log_lines[-60:]}


def ws_connect_upstream(app: Application, scheme: str, host: str, port: int,
                        req: HttpRequest):
    """Open raw TCP(+TLS) connection toward upstream for WS relay."""
    s = socket.create_connection((host, port), app.policy.limits.timeout_sec)
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


# bind helper onto Application
Application.ws_connect_upstream = ws_connect_upstream
