"""Unit tests: decoders, comparer, JWT/cookie analysis, tech detection, rules."""
import base64
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from owsi.analysis import (RuleEngine, analyze_cookies, analyze_jwt,  # noqa: E402
                           compare, decode, detect_technologies)
from owsi.http_model import HeaderList, HttpRequest, HttpResponse      # noqa: E402


# -------------------------------------------------------------------- decoder
def test_base64_roundtrip():
    assert decode("base64_encode", "hello") == base64.b64encode(b"hello").decode()
    assert decode("base64_decode", base64.b64encode(b"hi").decode()) == "hi"


def test_base32_url_html_hex_roundtrips():
    assert decode("base32_decode", decode("base32_encode", "owsi")) == "owsi"
    assert decode("url_decode", decode("url_encode", "a b&c/")) == "a b&c/"
    assert decode("html_decode", decode("html_encode", "<b>&x")) == "<b>&x"
    assert decode("hex_decode", decode("hex_encode", "ABC")) == "ABC"


def test_hash_ops_are_correct():
    assert decode("sha256", "abc") == hashlib.sha256(b"abc").hexdigest()
    assert decode("md5", "abc") == hashlib.md5(b"abc").hexdigest()


def test_json_prettify_and_minify():
    pretty = decode("json_pretty", '{"a":1,"b":[2,3]}')
    assert "\n" in pretty and '"a"' in pretty
    mini = decode("json_minify", '{ "a" : 1 }')
    assert mini == '{"a":1}'


def test_decoder_rejects_unknown_op():
    try:
        decode("nope", "x")
        assert False, "expected ValueError"
    except ValueError:
        pass


# ------------------------------------------------------------------- comparer
def test_compare_equal_inputs():
    r = compare("line1\nline2", "line1\nline2")
    assert r["similarity"] == 1.0
    assert r["addedLines"] == 0 and r["removedLines"] == 0
    assert r["diff"] == ""


def test_compare_reports_diff():
    r = compare("a\nb\nc", "a\nX\nc")
    assert r["similarity"] < 1.0
    assert r["changedBlocks"] >= 1
    assert "-b" in r["diff"] and "+X" in r["diff"]


# ------------------------------------------------------------------------ JWT
def _mk_jwt(payload, header=None, sig="c2ln"):
    def b64u(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj).encode()).rstrip(b"=").decode()
    h = b64u(header or {"alg": "HS256", "typ": "JWT"})
    p = b64u(payload)
    return f"{h}.{p}.{sig}"


def test_analyze_jwt_decodes_claims():
    tok = _mk_jwt({"sub": "alice", "exp": time.time() + 3600})
    r = analyze_jwt(tok)
    assert r["validStructure"] is True
    assert r["payload"]["sub"] == "alice"
    assert r["header"]["alg"] == "HS256"
    assert r["expired"] is False
    assert r["signaturePresent"] is True


def test_analyze_jwt_flags_alg_none_and_expired():
    none_tok = _mk_jwt({"sub": "x"}, header={"alg": "none", "typ": "JWT"}, sig="")
    obs = json.dumps(analyze_jwt(none_tok)).lower()
    assert "alg=none" in obs.replace(" ", "") or "none" in obs

    past = _mk_jwt({"sub": "x", "exp": 1_000_000})
    r2 = analyze_jwt(past)
    assert r2["expired"] is True
    assert any("EXPIRED" in o for o in r2["observations"])


def test_analyze_jwt_malformed():
    r = analyze_jwt("garbage")
    assert r["validStructure"] is False
    assert r["observations"]


# --------------------------------------------------------------------- cookies
def test_analyze_cookies_flags_insecure_set_cookie():
    req = HttpRequest(target="/", headers=HeaderList([("Host", "c.test")]))
    resp = HttpResponse(status=200, headers=HeaderList([
        ("Set-Cookie", "bad=value"),                     # no flags at all
        ("Set-Cookie", "good=v; Secure; HttpOnly; SameSite=Strict; Path=/")]))
    out = analyze_cookies(req, resp)
    names = {c["name"]: c for c in out}
    assert set(names) == {"bad", "good"}
    # insecure cookie accumulates flag warnings, secure one has none
    assert len(names["bad"]["flags"]) >= 2
    assert not any("missing" in f for f in names["good"]["flags"])


def test_analyze_cookies_includes_request_cookies():
    req = HttpRequest(target="/", headers=HeaderList([
        ("Host", "c.test"), ("Cookie", "sid=abc; theme=dark")]))
    resp = HttpResponse(status=200)
    names = {c["name"] for c in analyze_cookies(req, resp)}
    assert {"sid", "theme"} <= names


# ----------------------------------------------------------- tech detection
def test_detect_technologies_from_headers():
    req = HttpRequest(target="/", host="t.test")
    resp = HttpResponse(status=200, headers=HeaderList([
        ("Server", "nginx/1.22.0"),
        ("X-Powered-By", "PHP/8.1.2"),
        ("Set-Cookie", "JSESSIONID=abc; Path=/; HttpOnly")]),
        body=b"<html></html>")
    techs = detect_technologies(req, resp)
    assert "Nginx" in techs
    assert "PHP" in techs
    assert "Java" in techs


# ---------------------------------------------------------------- rules engine
def _req():
    return HttpRequest(method="GET", target="/x?q=1",
                       headers=HeaderList([("Host", "r.test"),
                                           ("User-Agent", "curl")]))


def test_rule_add_remove_set_header():
    eng = RuleEngine()
    eng.rules = [
        {"name": "add", "enabled": True, "phase": "request",
         "match": {}, "action": {"type": "addHeader", "name": "X-Test", "value": "1"}},
        {"name": "set", "enabled": True, "phase": "request",
         "match": {"field": "header:User-Agent", "pattern": "curl"},
         "action": {"type": "setHeader", "name": "User-Agent", "value": "OWSI"}},
        {"name": "rm", "enabled": True, "phase": "request",
         "match": {"field": "path", "regex": "^/x"},
         "action": {"type": "removeHeader", "name": "X-Remove"}},
    ]
    req = _req()
    req.headers.add("X-Remove", "bye")
    dropped, logs = eng.apply("request", req)
    assert dropped is False
    assert req.headers.get("X-Test") == "1"
    assert req.headers.get("User-Agent") == "OWSI"
    assert req.headers.get_all("X-Remove") == []
    assert len(logs) == 3


def test_rule_disabled_and_wrong_phase_noop():
    eng = RuleEngine()
    eng.rules = [{"name": "off", "enabled": False, "phase": "request",
                  "match": {}, "action": {"type": "drop"}}]
    dropped, logs = eng.apply("request", _req())
    assert dropped is False and logs == []


def test_rule_drop_and_regex_match():
    eng = RuleEngine()
    eng.rules = [{"name": "block-admin", "enabled": True, "phase": "request",
                  "match": {"field": "url", "regex": "/admin.*"},
                  "action": {"type": "drop"}}]
    req = _req()
    req.target = "/admin/panel"
    dropped, logs = eng.apply("request", req)
    assert dropped is True
    assert any("DROP" in l for l in logs)


def test_rule_mark_action_does_not_drop():
    eng = RuleEngine()
    eng.rules = [{"name": "tag", "enabled": True, "phase": "request",
                  "match": {"field": "method", "pattern": "get"},
                  "action": {"type": "mark", "tag": "interesting"}}]
    dropped, logs = eng.apply("request", _req())
    assert dropped is False
    assert any("MARK" in l for l in logs)


def test_rule_response_body_replace_fixes_content_length():
    eng = RuleEngine()
    eng.rules = [{"name": "redact", "enabled": True, "phase": "response",
                  "match": {"status": 200},
                  "action": {"type": "replaceBody", "find": "SECRET",
                             "replace": "[redacted]"}}]
    resp = HttpResponse(status=200, headers=HeaderList(
        [("Content-Length", "19")]), body=b"value is SECRET!!! ok")
    dropped, logs = eng.apply("response", resp)
    assert b"SECRET" not in resp.body
    assert b"[redacted]" in resp.body
    assert resp.headers.get("Content-Length") == str(len(resp.body))
