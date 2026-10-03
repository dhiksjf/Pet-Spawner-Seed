"""Unit tests: scope matching, security policy gate, event bus, WS frame codec."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from owsi.events import EventBus                                  # noqa: E402
from owsi.modules import WSEngine                                 # noqa: E402
from owsi.policy import (RateLimiter, SecurityPolicy, TargetScope)  # noqa: E402


# ------------------------------------------------------------------ scope math
def _pol(mode="LAB", **scope_kw):
    return SecurityPolicy(mode=mode, scope=TargetScope(**scope_kw))


def test_lab_mode_allows_loopback_denies_public():
    p = _pol("LAB")
    ok, _ = p.target_allowed("http", "127.0.0.1", 80)
    assert ok is True
    ok, why = p.target_allowed("http", "example.com", 80)
    assert ok is False and "scope" in why


def test_wildcard_and_exact_host_matching():
    p = _pol("MANUAL_ACTIVE", allowed_hosts=["*.app.test", "exact.test"])
    assert p.host_in_scope("api.app.test") is True
    assert p.host_in_scope("app.test") is True          # *.x matches x itself? -> via endswith(".test")? verify
    assert p.host_in_scope("exact.test") is True
    assert p.host_in_scope("other.test") is False


def test_excluded_host_wins_over_allowed():
    p = _pol("LAB", allowed_hosts=["*"], excluded_hosts=["secret.test"])
    assert p.host_in_scope("ok.test") or p.host_in_scope("127.0.0.1")
    assert p.host_in_scope("secret.test") is False


def test_port_scheme_and_path_gates():
    p = _pol("LAB", allowed_ports=[80, 443])
    ok, why = p.target_allowed("http", "127.0.0.1", 6667)
    assert not ok and "port" in why
    ok, why = p.target_allowed("ftp", "127.0.0.1", 80)
    assert not ok and "scheme" in why

    p2 = _pol("LAB", allowed_paths=["/api/*"])
    ok, why = p2.target_allowed("http", "127.0.0.1", 80, "/admin/db")
    assert not ok and "path" in why
    ok, _ = p2.target_allowed("http", "127.0.0.1", 80, "/api/items")
    assert ok


def test_host_with_embedded_port_is_normalised():
    p = _pol("LAB")
    ok, _ = p.target_allowed("http", "127.0.0.1:8080", 80)
    assert ok   # port picked up from host:port string


# ---------------------------------------------------------------- policy gate
def test_passive_blocks_everything_active():
    p = _pol("PASSIVE")
    try:
        p.check_active_send("GET", "http", "127.0.0.1", 80, "/", origin="manual")
        assert False, "expected PermissionError"
    except PermissionError as e:
        assert "PASSIVE" in str(e)


def test_manual_allows_get_blocks_automated_dangerous_without_approval():
    # MANUAL_ACTIVE is default-deny: user must explicitly list the target host
    p = _pol("MANUAL_ACTIVE", allowed_hosts=["127.0.0.1"])
    p.check_active_send("GET", "http", "127.0.0.1", 80, "/")       # ok
    # an unlisted host stays blocked even in MANUAL_ACTIVE
    try:
        p.check_active_send("GET", "http", "10.0.0.5", 80, "/")
        assert False
    except PermissionError as e:
        assert "scope" in str(e)
    # POST from fuzzer without approval → blocked (dangerous + automated)
    try:
        p.check_active_send("POST", "http", "127.0.0.1", 80, "/",
                            origin="fuzzer")
        assert False
    except PermissionError as e:
        assert "approval" in str(e)
    # after explicit one-time approval it passes exactly once
    p.approve_action("job42")
    p.check_active_send("POST", "http", "127.0.0.1", 80, "/",
                        origin="fuzzer", action_id="job42")
    try:
        p.check_active_send("POST", "http", "127.0.0.1", 80, "/",
                            origin="fuzzer", action_id="job42")     # token consumed
        assert False
    except PermissionError:
        pass


def test_user_initiated_post_from_manual_origin_allowed():
    p = _pol("MANUAL_ACTIVE", allowed_hosts=["127.0.0.1"])
    p.check_active_send("POST", "http", "127.0.0.1", 80, "/login",
                        origin="manual")            # click IS the approval


def test_unknown_mode_rejected_by_set_mode():
    p = _pol("LAB")
    try:
        p.set_mode("YOLO")
        assert False
    except ValueError:
        pass


# ---------------------------------------------------------------- rate limiter
def test_rate_limiter_throttles_bursts():
    rl = RateLimiter(5)               # 5 tokens burst
    drained = 0
    for _ in range(10):
        if rl.acquire(timeout=0):
            drained += 1
    assert drained <= 6               # roughly the bucket size
    assert rl.acquire(timeout=1.2)    # refills within ~1s


# ------------------------------------------------------------------- event bus
def test_event_bus_publish_subscribe_unsubscribe():
    bus = EventBus()
    got = []
    unsub = bus.subscribe("demo", lambda e: got.append(e))
    bus.publish("demo", {"x": 1})
    unsub()
    bus.publish("demo", {"x": 2})
    assert [g["x"] for g in got] == [1]
    assert got[0]["event"] == "demo" and "seq" in got[0] and "ts" in got[0]


def test_event_bus_wildcard_and_recent_ring():
    bus = EventBus()
    seen = []
    bus.subscribe("*", lambda e: seen.append(e["event"]))
    for i in range(3):
        bus.publish(f"ev{i}", {"i": i})
    assert seen == ["ev0", "ev1", "ev2"]
    assert len(bus.recent) == 3


def test_event_bus_broken_subscriber_does_not_break_pipeline():
    bus = EventBus()
    ok = []
    bus.subscribe("z", lambda e: (_ for _ in ()).throw(RuntimeError("boom")))
    bus.subscribe("z", lambda e: ok.append(e))
    bus.publish("z", {"a": 1})
    assert len(ok) == 1


# ------------------------------------------------------------- WS frame codec
def test_ws_frame_encode_decode_roundtrip_masked():
    payload = b"hello websocket \xc3\xa9"
    raw = WSEngine._encode_frame(0x1, payload, mask=True)
    # emulate a socket that serves the bytes
    class FakeSock:
        def __init__(self, data):
            self.data = data

        def recv(self, n):
            out, self.data = self.data[:n], self.data[n:]
            if not out:
                raise ConnectionError("closed")
            return out
    opcode, dec, _ = WSEngine._read_frame(FakeSock(raw))
    assert opcode == 0x1
    assert dec == payload


def test_ws_frame_extended_lengths():
    medium = b"x" * 300
    big = b"y" * 70_000
    for op, pl in ((0x1, medium), (0x2, big)):
        raw = WSEngine._encode_frame(op, pl, mask=False)

        class FakeSock:
            def __init__(self, data):
                self.data = data

            def recv(self, n):
                out, self.data = self.data[:n], self.data[n:]
                if not out:
                    raise ConnectionError("closed")
                return out
        opcode, dec, _ = WSEngine._read_frame(FakeSock(raw))
        assert opcode == op and dec == pl
