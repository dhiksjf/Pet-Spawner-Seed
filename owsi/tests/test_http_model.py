"""Unit tests: HTTP parsing, headers, cookies, URL/query/body (spec §100)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from owsi.http_model import (HeaderList, HttpRequest, HttpResponse,  # noqa: E402
                             parse_headers)


# --------------------------------------------------------------------- headers
def test_parse_headers_keeps_first_header_line():
    blob = b"Host: example.com\r\nAccept: */*\r\nX-A: 1\r\n\r\nrest"
    h, consumed = parse_headers(blob)
    assert h.get("Host") == "example.com"
    assert h.get("Accept") == "*/*"
    assert h.get("x-a") == "1"          # case-insensitive lookup
    assert blob[consumed:] == b"rest"


def test_header_list_multi_value_and_set_remove():
    h = HeaderList([("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
    assert h.get_all("set-cookie") == ["a=1", "b=2"]
    h.set("Set-Cookie", "c=3")
    assert h.get_all("Set-Cookie") == ["c=3"]
    h.remove("Set-Cookie")
    assert h.get_all("Set-Cookie") == []
    assert "missing" not in h


def test_obs_fold_continuation():
    blob = b"X-Long: part1\r\n  part2\r\n\r\n"
    h, _ = parse_headers(blob)
    assert h.get("X-Long") == "part1 part2"


# ---------------------------------------------------------------- request line
def test_request_parse_origin_form_with_host_header():
    raw = (b"GET /a/b?x=1&y=2 HTTP/1.1\r\nHost: lab.local:8080\r\n"
           b"Cookie: s=1; t=2\r\n\r\n")
    req = HttpRequest.parse(raw)
    assert req.method == "GET"
    assert req.host == "lab.local"
    assert req.port == 8080
    assert req.hostname == "lab.local"
    assert req.path() == "/a/b"
    assert req.query() == "x=1&y=2"
    assert ("x", "1") in req.params()
    assert req.url() == "http://lab.local:8080/a/b?x=1&y=2"


def test_request_parse_absolute_uri_form():
    raw = (b"POST https://api.test/v1/items?k=9 HTTP/1.1\r\n"
           b"Content-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}")
    req = HttpRequest.parse(raw)
    assert req.scheme == "https"
    assert req.host == "api.test"
    assert req.port == 443
    assert req.target == "/v1/items?k=9"
    assert req.body == b'{"a":1}'
    assert req.url() == "https://api.test/v1/items?k=9"


def test_request_parse_defaults_when_no_host_header():
    raw = b"GET /x HTTP/1.1\r\nAccept: */*\r\n\r\n"
    req = HttpRequest.parse(raw, default_scheme="https",
                           default_host="fallback.test", default_port=8443)
    assert req.host == "fallback.test"
    assert req.port == 8443
    assert req.scheme == "https"


def test_request_raw_roundtrip():
    raw = (b"PUT /res/1 HTTP/1.1\r\nHost: z.test\r\nContent-Type: text/plain\r\n"
           b"Content-Length: 5\r\n\r\nhello")
    req = HttpRequest.parse(raw)
    again = HttpRequest.parse(req.raw())
    assert again.method == "PUT"
    assert again.host == "z.test"
    assert again.body == b"hello"
    assert again.headers.get("Content-Length") == "5"


def test_bad_request_line_raises():
    try:
        HttpRequest.parse(b"NOTAREQUESTLINE\r\n\r\n")
        assert False, "expected ValueError"
    except ValueError:
        pass


# ---------------------------------------------------------------- parameters
def test_params_query_urlencoded_and_json_locations():
    req = HttpRequest(
        method="POST", target="/search?q=abc",
        headers=HeaderList([("Host", "p.test"),
                            ("Content-Type", "application/x-www-form-urlencoded")]),
        body=b"page=2&sort=asc")
    locs = dict((n, l) for n, l in req.param_locations())
    assert locs["q"] == "query"
    assert locs["page"] == "body"
    assert locs["sort"] == "body"


def test_param_locations_json_flattened_keys():
    import json as _json
    req = HttpRequest(method="POST", target="/api",
                      headers=HeaderList([("Host", "j.test"),
                                          ("Content-Type", "application/json")]),
                      body=_json.dumps({"user": {"name": "a"},
                                        "tags": [{"k": "v"}]}).encode())
    names = {n for n, l in req.param_locations() if l == "json"}
    assert "user.name" in names
    assert "tags[0].k" in names


def test_param_locations_cookie_names():
    req = HttpRequest(target="/", headers=HeaderList(
        [("Host", "c.test"), ("Cookie", "session=abc; theme=dark")]))
    locs = req.param_locations()
    assert ("session", "cookie") in locs and ("theme", "cookie") in locs


def test_with_param_replaces_in_each_location():
    req = HttpRequest(method="GET", target="/s?q=orig&id=7",
                      headers=HeaderList([("Host", "w.test")]))
    m = req.with_param("q", "MUT", "query")
    assert "q=MUT" in m.target and "id=7" in m.target
    assert req.target == "/s?q=orig&id=7"      # original untouched (clone)

    form = HttpRequest(method="POST", target="/f",
                       headers=HeaderList([("Host", "w.test"),
                                           ("Content-Type",
                                            "application/x-www-form-urlencoded")]),
                       body=b"a=1")
    fm = form.with_param("a", "2", "body")
    assert fm.body == b"a=2"
    assert fm.headers.get("Content-Length") == "3"

    ck = HttpRequest(target="/", headers=HeaderList(
        [("Host", "w.test"), ("Cookie", "sid=1; x=2")]))
    cm = ck.with_param("sid", "zzz", "cookie")
    assert cm.headers.get("Cookie") == "sid=zzz; x=2"


def test_clone_gets_fresh_id():
    req = HttpRequest(target="/", host="k.test")
    c = req.clone()
    assert c.id != req.id
    assert c.host == "k.test"


# ------------------------------------------------------------------ responses
# {"a":1} is 7 bytes; fixture header says 6 (real-world mismatch: the parser
# must preserve the wire body exactly, not "fix" it to the advertised length)
RESP = (b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n"
        b"Content-Length: 6\r\n\r\n{\"a\":1}")


def test_response_parse():
    r = HttpResponse.parse(RESP)
    assert r.status == 201
    assert r.reason == "Created"
    assert r.content_type() == "application/json"
    assert r.json() == {"a": 1}
    assert r.raw().endswith(b"{\"a\":1}")


def test_response_gzip_decoded_body():
    import gzip as gz
    payload = gz.compress(b"hello compressed world")
    r = HttpResponse(status=200,
                     headers=HeaderList([("Content-Encoding", "gzip")]),
                     body=payload)
    assert r.decoded_body() == b"hello compressed world"
    assert r.text() == "hello compressed world"


def test_response_summary_fields():
    r = HttpResponse.parse(RESP)
    s = r.summary()
    # summary reports the actual decoded body length on the wire (7 bytes),
    # not the advertised-but-wrong Content-Length header (6)
    assert s["status"] == 201 and s["length"] == 7
    assert s["contentType"] == "application/json"


def test_set_body_updates_content_length():
    req = HttpRequest(headers=HeaderList([("Content-Length", "2")]))
    req.set_body(b"1234567890")
    assert req.headers.get("Content-Length") == "10"
