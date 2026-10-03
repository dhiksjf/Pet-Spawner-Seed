"""Shared pytest fixtures for the OWSI test suite (spec §100).

Everything runs against 127.0.0.1 only — no internet access is ever needed.
"""
import os
import socket
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from owsi.core import Application                    # noqa: E402
from owsi.server import serve_control               # noqa: E402
from owsi.testsite import TestSite                  # noqa: E402


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="session")
def tmp_root(tmp_path_factory):
    return tmp_path_factory.mktemp("owsi")


@pytest.fixture()
def app(tmp_root):
    """Fresh Application with its own data dir (isolated SQLite project)."""
    d = str(tmp_root / f"app-{time.time_ns()}")
    a = Application(d)
    yield a
    a.db.close()


class FakeProvider:
    """Minimal OpenAI-compatible chat-completions server on localhost.

    Lets the AI integration test verify the full copilot pipeline (context
    building → provider call → structured parse → proposal approval) without
    any real LLM or internet dependency.
    """

    def __init__(self, reply_body: dict):
        import json as _json
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        body = _json.dumps(reply_body).encode()

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.port = free_port()
        self._srv = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        import threading
        self._t = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._t.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()


@pytest.fixture()
def fake_openai_provider():
    created = []

    def _make(content: str):
        p = FakeProvider({"choices": [{"message": {"role": "assistant",
                                                   "content": content}}]})
        created.append(p)
        return p
    yield _make
    for p in created:
        p.stop()


@pytest.fixture()
def site(tmp_root):
    """OWSI internal test website over plain HTTP."""
    s = TestSite(port=free_port(), data_dir=str(tmp_root / "site"))
    s.start()
    yield s
    s.stop()


@pytest.fixture()
def https_site(tmp_root):
    """Internal test website with HTTPS (test certificate environment §102)."""
    s = TestSite(port=free_port(), https_port=free_port(),
                 data_dir=str(tmp_root / "site-tls"))
    s.start()
    yield s
    s.stop()


@pytest.fixture()
def control(app):
    """Running OWSI control API (REST + WS feed) on a free localhost port."""
    port = free_port()
    srv = serve_control(app, ("127.0.0.1", port))
    app.api_base = f"http://127.0.0.1:{port}"
    yield app
    srv.shutdown()
