"""Unit tests: project database persistence (history, findings, WS frames, kv)."""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from owsi.db import SCHEMA_VERSION, ProjectDB                       # noqa: E402
from owsi.http_model import HeaderList, HttpRequest, HttpResponse    # noqa: E402


def _pair(url="/a?x=1", status=200):
    req = HttpRequest(method="GET", target=url,
                      headers=HeaderList([("Host", "db.test")]),
                      scheme="http", host="db.test", port=80)
    resp = HttpResponse(status=status, reason="OK" if status == 200 else "Err",
                        headers=HeaderList([("Content-Type", "text/html")]),
                        body=b"<html>hi</html>")
    return req, resp


def test_add_and_get_history_roundtrip(tmp_path):
    db = ProjectDB(str(tmp_path / "p.db"))
    req, resp = _pair()
    entry = db.add_history(req, resp, tech="Nginx")
    got = db.get_history_entry(entry["id"])
    assert got["url"] == req.url()
    assert got["status"] == 200
    assert bytes(got["request_raw"]).startswith(b"GET /a?x=1 HTTP/1.1")
    assert b"HTTP/1.1 200 OK" in bytes(got["response_raw"])
    r2 = db.history_request(entry["id"])
    assert r2.host == "db.test" and r2.target == "/a?x=1"
    db.close()


def test_list_history_filters_pagination_and_search(tmp_path):
    db = ProjectDB(str(tmp_path / "p.db"))
    for i in range(5):
        db.add_history(*_pair(url=f"/page{i}"))
    bad = HttpRequest(target="/zap", host="other.test", port=80)
    db.add_history(bad, None)
    rows = db.list_history(limit=3)
    assert len(rows) == 3
    assert db.count_history() == 6
    by_host = db.list_history(host="other.test")
    assert len(by_host) == 1 and by_host[0]["method"] == "GET"
    found = db.list_history(search="page2")
    assert any(e["path"] == "/page2" for e in found)
    offset_rows = db.list_history(limit=10, offset=4)
    assert len(offset_rows) == 2
    db.close()


def test_update_meta_tags_note_comment(tmp_path):
    db = ProjectDB(str(tmp_path / "p.db"))
    e = db.add_history(*_pair())
    db.update_history_meta(e["id"], tags=["fuzzer", "high"], note="mine",
                           comment="hello")
    got = db.get_history_entry(e["id"])
    assert got["tags"] == ["fuzzer", "high"]
    assert got["note"] == "mine"
    assert got["comment"] == "hello"
    db.close()


def test_delete_history_ids_before_all(tmp_path):
    db = ProjectDB(str(tmp_path / "p.db"))
    ids = [db.add_history(*_pair(url=f"/d{i}"))["id"] for i in range(4)]
    assert db.delete_history(ids=[ids[0], ids[1]]) == 2
    assert db.count_history() == 2
    assert db.delete_history(all_=True) == 2
    assert db.count_history() == 0
    db.close()


def test_findings_lifecycle(tmp_path):
    db = ProjectDB(str(tmp_path / "p.db"))
    f = db.add_finding({"severity": "high", "title": "SQLi", "url": "http://x/1",
                        "description": "d", "evidence": "e",
                        "recommendation": "r"})
    assert db.finding_exists(f["id"]) is True
    assert db.finding_exists("nope") is False
    # dedup key: same title+url must not create a second row
    dup = db.add_finding({"severity": "low", "title": "SQLi", "url": "http://x/1"})
    assert dup["id"] == f["id"], "dedup by (title,url) should reuse existing id"
    db.add_finding({"severity": "low", "title": "Missing CSP", "url": "http://x/1"})
    listing = db.list_findings()
    assert len(listing) == 2
    # sorted by severity: high first
    assert listing[0]["severity"] == "high"
    assert db.set_finding_status(f["id"], "fixed") is True
    assert db.list_findings()[0]["status"] == "fixed"
    assert db.set_finding_status("missing-id", "open") is False
    db.close()


def test_sitemap_groups_by_host_path(tmp_path):
    db = ProjectDB(str(tmp_path / "p.db"))
    db.add_history(*_pair(url="/same"))
    db.add_history(*_pair(url="/same"))
    db.add_history(*_pair(url="/other"))
    nodes = db.sitemap()
    m = {(n["host"], n["path"]): n for n in nodes}
    assert m[("db.test", "/same")]["count"] == 2
    assert ("db.test", "/other") in m
    db.close()


def test_ws_frames_and_sessions(tmp_path):
    db = ProjectDB(str(tmp_path / "p.db"))
    db.add_ws_frame("s1", "to-server", "text", b"ping")
    db.add_ws_frame("s1", "to-client", "text", b"pong")
    db.add_ws_frame("s2", "to-server", "binary", b"\x00\x01")
    frames = db.ws_frames("s1")
    assert len(frames) == 2
    assert frames[0]["direction"] == "to-server"      # chronological
    assert frames[0]["payload"] == "ping"
    sessions = {s["sessionId"]: s["frames"] for s in db.list_ws_sessions()}
    assert sessions == {"s1": 2, "s2": 1}
    db.close()


def test_ai_conversation_history(tmp_path):
    db = ProjectDB(str(tmp_path / "p.db"))
    db.add_ai_message("c1", "user", "is this vulnerable?")
    db.add_ai_message("c1", "assistant", "maybe")
    db.add_ai_message("c2", "user", "other conv")
    hist = db.ai_history("c1")
    assert [m["role"] for m in hist] == ["user", "assistant"]
    assert len(db.ai_history("c2")) == 1
    db.close()


def test_kv_store_json_values(tmp_path):
    db = ProjectDB(str(tmp_path / "p.db"))
    db.kv_set("k", {"nested": [1, 2, 3]})
    assert db.kv_get("k") == {"nested": [1, 2, 3]}
    assert db.kv_get("absent", default="dflt") == "dflt"
    db.kv_set("k", 42)
    assert db.kv_get("k") == 42
    db.close()


def test_schema_version_recorded_and_reopen_is_safe(tmp_path):
    path = str(tmp_path / "p.db")
    db = ProjectDB(path)
    db.add_history(*_pair())
    db.close()
    db2 = ProjectDB(path)                     # re-run migrations on existing DB
    assert db2.count_history() == 1
    raw = sqlite3.connect(path)
    ver = raw.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()[0]
    assert int(ver) == SCHEMA_VERSION
    db2.close()
