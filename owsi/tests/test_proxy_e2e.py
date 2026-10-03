"""End-to-end proxy verification through the REAL interception engine.

Covers (spec §15/§16, §100):
  * plain HTTP proxied via absolute-URI request line
  * HTTPS CONNECT + MITM: leaf cert presented is signed by the OWSI CA and
    validates against it with full TLS verification
  * scope enforcement (out-of-scope hosts blocked with 403)
  * interceptor flags: drop request / modify response
  * history recording + passive-analysis findings in the DB
All traffic stays on 127.0.0.1 against the built-in TestSite lab.
"""
import json
import socket
import ssl
import threading
import time

import pytest

from owsi.http_client import send_request
from owsi.http_model import HeaderList, HttpRequest


@pytest.fixture()
def lab(tmp_root, app):
    """TestSite (http+https) + running ProxyEngine wired to `app`."""
    from conftest import free_port
    from owsi.testsite import TestSite

    site = TestSite(port=free_port(), https_port=free_port(),
                    data_dir=str(tmp_root / f"lab-{time.time_ns()}"))
    site.start()

    pport = free_port()
    for _ in range(20):
        try:
            app.proxy.start(("127.0.0.1", pport))
            break
        except OSError:
            pport = free_port()
    else:
        pytest.fail("could not bind proxy port")

    app.policy.update({
        "mode": "LAB",
        "scope": {"allowedHosts": ["127.0.0.1"],
                  # dynamic lab ports must be in the port allowlist too
                  "allowedPorts": [site.port, site.https_port],
                  "allowedSchemes": ["http", "https"]},
    })
    # short intercept timeout so tests never hang on an unresolved item
    app.interceptor.set_flags(timeout=8.0)
    yield {"proxy": ("127.0.0.1", pport), "http": site.port,
           "https": site.https_port, "app": app}
    app.proxy.stop()
    site.stop()


def _get(lab, path, scheme="http"):
    """Send a request THROUGH the OWSI proxy using its own HTTP client.

    Absolute-URI request line (proxy form); ConnectionPool connects directly
    to the proxy address, so this exercises the real interception pipeline.
    """
    host, port = "127.0.0.1", lab["http"] if scheme == "http" else lab["https"]
    req = HttpRequest(
        method="GET",
        target=f"{scheme}://{host}:{port}{path}",
        version="HTTP/1.1",
        headers=HeaderList([("Host", f"{host}:{port}"),
                            ("Connection", "close")]))
    req.scheme, req.host, req.port = scheme, host, port
    return send_request(req, timeout=10)


# ---------------------------------------------------------------------------
def test_plain_http_through_proxy(lab):
    resp = _get(lab, "/")
    assert resp.status == 200
    assert len(resp.body) > 0
    hist = lab["app"].db.list_history(limit=50)
    assert any(h["host"] == "127.0.0.1" and h["path"] == "/" for h in hist), \
        "proxied request not recorded in history"
    assert any(h["source"] == "proxy" for h in hist)


def test_https_connect_mitm_validated(lab):
    """CONNECT tunnel → MITM leaf must chain-verify against the OWSI CA."""
    ctx = ssl.create_default_context(cafile=lab["app"].ca.ca_cert_path)
    s = socket.create_connection(lab["proxy"], timeout=10)
    s.sendall(f"CONNECT 127.0.0.1:{lab['https']} HTTP/1.1\r\n"
              f"Host: 127.0.0.1:{lab['https']}\r\n\r\n".encode())
    banner = s.recv(1024)
    assert b"200" in banner, banner
    ts = ctx.wrap_socket(s, server_hostname="127.0.0.1")   # full verification
    issuer = str(ts.cert()["issuer"])
    assert "OWSI" in issuer, f"leaf not signed by OWSI CA: {issuer}"
    ts.sendall(f"GET /api/items HTTP/1.1\r\n"
               f"Host: 127.0.0.1:{lab['https']}\r\n"
               f"Connection: close\r\n\r\n".encode())
    data = b""
    while True:
        chunk = ts.recv(4096)
        if not chunk:
            break
        data += chunk
    ts.close()
    head, _, body = data.partition(b"\r\n\r\n")
    assert b"200 OK" in head, head[:200]
    parsed = json.loads(body.decode(errors="replace"))
    assert isinstance(parsed, list) and len(parsed) >= 1
    # intercepted https request landed in history
    hist = lab["app"].db.list_history(limit=50)
    assert any(h["scheme"] == "https" and h["path"] == "/api/items"
               for h in hist), "MITM'd https request missing from history"


def test_out_of_scope_blocked(lab):
    lab["app"].policy.update({"scope": {"allowedHosts": ["example.com"]}})
    resp = _get(lab, "/")
    assert resp.status == 403, f"expected policy 403, got {resp.status}"
    assert b"outside target scope" in resp.body or b"scope" in resp.body.lower()
    lab["app"].policy.update({"scope": {"allowedHosts": ["127.0.0.1"]}})
    assert _get(lab, "/").status == 200


def test_intercept_drop_request(lab):
    ic = lab["app"].interceptor
    ic.set_flags(request=True)
    got = {}

    def sender():
        try:
            got["resp"] = _get(lab, "/api/items")
        except Exception as e:
            got["err"] = repr(e)

    t = threading.Thread(target=sender)
    t.start()
    pend = []
    deadline = time.time() + 8
    while time.time() < deadline:
        pend = [p for p in ic.pending() if p["kind"] == "request"]
        if pend:
            break
        time.sleep(0.05)
    assert pend, "intercepted request never surfaced in pending list"
    ok = ic.resolve(pend[0]["id"], "drop")
    assert ok
    t.join(12)
    ic.set_flags(request=False)
    status = getattr(got.get("resp"), "status", None)
    assert "err" in got or status == 508, got


def test_intercept_modify_response(lab):
    ic = lab["app"].interceptor
    ic.set_flags(response=True)
    got = {}

    def sender():
        try:
            got["resp"] = _get(lab, "/api/items")
        except Exception as e:
            got["err"] = repr(e)

    t = threading.Thread(target=sender)
    t.start()
    pend = []
    deadline = time.time() + 8
    while time.time() < deadline:
        pend = [p for p in ic.pending() if p["kind"] == "response"]
        if pend:
            break
        time.sleep(0.05)
    assert pend, "intercepted response never surfaced in pending list"
    new_raw = ("HTTP/1.1 418 I Am A Teapot\r\n"
               "Content-Type: text/plain\r\n"
               "Content-Length: 3\r\n"
               "Connection: close\r\n\r\nok!").encode("iso-8859-1").decode(
                   "latin1")
    assert ic.resolve(pend[0]["id"], "forward", raw_message=new_raw)
    t.join(12)
    ic.set_flags(response=False)
    r = got.get("resp")
    assert r is not None, f"sender failed: {got}"
    assert r.status == 418, f"response modification failed: {r.status}"
    assert r.body == b"ok!"


def test_passive_analysis_finding_recorded(lab):
    _get(lab, "/login")
    _get(lab, "/")
    time.sleep(0.3)
    findings = lab["app"].db.list_findings()
    assert len(findings) >= 1, "passive analyzer produced no findings"
