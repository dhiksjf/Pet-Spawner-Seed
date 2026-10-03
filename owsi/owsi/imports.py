"""Importers: cURL, HAR, OpenAPI/Swagger, Postman collections, raw HTTP (spec 28-30).

All imported content is treated as UNTRUSTED data (spec 128): we parse it into
HttpRequest objects and never execute anything from it.
"""
from __future__ import annotations

import json
import shlex
import urllib.parse
from typing import List, Optional

from .http_model import HttpRequest, HttpResponse


# --------------------------------------------------------------------- cURL
def parse_curl(cmd: str) -> HttpRequest:
    """Parse a curl command line into an HttpRequest. Supports common flags:
    -X/--request, -H/--header, -d/--data(-binary/--data-raw/--data-urlencode),
    -b/--cookie, -u/--user, --url, and a bare quoted URL."""
    toks = shlex.split(cmd)
    if not toks:
        raise ValueError("empty curl command")
    if toks[0].strip().lower() in ("curl", "curl.exe"):
        toks = toks[1:]
    method = ""
    headers: List[tuple] = []
    body: Optional[bytes] = None
    url = ""
    i = 0
    while i < len(toks):
        t = toks[i]
        nxt = toks[i + 1] if i + 1 < len(toks) else ""
        if t in ("-X", "--request"):
            method = nxt; i += 2; continue
        if t in ("-H", "--header"):
            k, _, v = nxt.partition(":")
            headers.append((k.strip(), v.strip())); i += 2; continue
        if t in ("-d", "--data", "--data-raw", "--data-binary",
                 "--data-urlencode"):
            body = nxt.encode(); i += 2; continue
        if t in ("-b", "--cookie"):
            headers.append(("Cookie", nxt)); i += 2; continue
        if t == "-u" or t == "--user":
            import base64
            token = base64.b64encode(nxt.encode()).decode()
            headers.append(("Authorization", f"Basic {token}")); i += 2; continue
        if t in ("--url",):
            url = nxt; i += 2; continue
        if t.startswith("-"):
            i += 2 if nxt and not nxt.startswith("http") else 1
            continue
        if not url and (t.startswith("http") or t.startswith("'")
                        or t.startswith('"')):
            url = t
        i += 1
    if not url:
        raise ValueError("no URL found in curl command")
    return build_request_from_url(url, method or ("POST" if body else "GET"),
                                  headers, body)


def build_request_from_url(url: str, method: str, headers: List[tuple],
                           body: Optional[bytes]) -> HttpRequest:
    sp = urllib.parse.urlsplit(url)
    if sp.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme '{sp.scheme}'")
    host = sp.hostname or ""
    port = sp.port or (443 if sp.scheme == "https" else 80)
    req = HttpRequest(method=method.upper(),
                      target=(sp.path or "/") + (("?" + sp.query) if sp.query
                                                 else ""),
                      scheme=sp.scheme, host=host, port=port)
    has_host = any(k.lower() == "host" for k, _ in headers)
    if not has_host:
        req.headers.add("Host", host + (f":{port}" if port not in (80, 443)
                                        else ""))
    for k, v in headers:
        if k:
            req.headers.add(k, v)
    if body is not None:
        req.set_body(body)
        if "Content-Type" not in req.headers:
            req.headers.set("Content-Type", "application/x-www-form-urlencoded")
    req.source = "curl-import"
    return req


# ---------------------------------------------------------------------- HAR
def import_har(app, har: dict) -> dict:
    """Import HAR 1.1 (Chrome/Firefox/DevTools exports) into history."""
    entries = (har.get("log") or {}).get("entries") or []
    added = 0
    skipped = 0
    for e in entries:
        try:
            req_d = e.get("request") or {}
            res_d = e.get("response") or {}
            url = req_d.get("url", "")
            sp = urllib.parse.urlsplit(url)
            if sp.scheme not in ("http", "https"):
                skipped += 1
                continue
            host = sp.hostname or ""
            port = sp.port or (443 if sp.scheme == "https" else 80)
            req = HttpRequest(method=req_d.get("method", "GET").upper(),
                              target=(sp.path or "/") +
                              (("?" + sp.query) if sp.query else ""),
                              scheme=sp.scheme, host=host, port=port)
            for h in req_d.get("headers") or []:
                req.headers.add(h.get("name", "X"), str(h.get("value", "")))
            pd = req_d.get("postData") or {}
            if pd.get("text"):
                req.set_body(pd["text"].encode("utf-8", "replace"))
            resp = HttpResponse(status=int(res_d.get("status") or 0),
                                reason=res_d.get("statusText", ""))
            for h in res_d.get("headers") or []:
                resp.headers.add(h.get("name", "X"), str(h.get("value", "")))
            cd = res_d.get("content") or {}
            if cd.get("text"):
                resp.body = cd["text"].encode("utf-8", "replace")
            tm = float((e.get("timings") or {}).get("wait") or 0)
            resp.elapsed_ms = tm
            req.source = "har-import"
            app.db.add_history(req, resp)
            added += 1
        except Exception:
            skipped += 1
    return {"ok": True, "imported": added, "skipped": skipped}


# ------------------------------------------------------------------ OpenAPI
def import_openapi(app, spec: dict) -> dict:
    """Parse OpenAPI 3.x / Swagger 2.x into an endpoint catalog and repeater
    tabs with example requests. Nothing is sent automatically."""
    paths = spec.get("paths") or {}
    base = ""
    servers = spec.get("servers") or []
    if servers:
        base = servers[0].get("url", "")
    elif spec.get("host"):
        schemes = spec.get("schemes") or ["https"]
        base = f"{schemes[0]}://{spec['host']}{spec.get('basePath', '')}"
    sp = urllib.parse.urlsplit(base or "https://example.invalid")
    scheme = sp.scheme or "https"
    host = sp.hostname or ""
    port = sp.port or (443 if scheme == "https" else 80)
    endpoints = []
    made_tabs = 0
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch",
                                      "delete", "head", "options"):
                continue
            params = []
            if isinstance(op, dict):
                params = op.get("parameters") or []
            q = "&".join(p.get("name", "") + "=" + str(
                (p.get("schema") or p).get("default", ""))
                for p in params if p.get("in") == "query")
            full_path = (base.split("//", 1)[-1].partition("/")[2]
                         if base and not spec.get("host") else "")
            target = "/" + "/".join(x for x in
                                    [full_path.strip("/"), path.lstrip("/")] if x)
            if q:
                target += "?" + q
            req = HttpRequest(method=method.upper(), target=target,
                              scheme=scheme, host=host, port=port)
            req.headers.add("Host", host)
            req.source = "openapi-import"
            endpoints.append({"method": req.method, "path": target,
                              "summary": (op or {}).get("summary", "")
                              if isinstance(op, dict) else "",
                              "params": [p.get("name") for p in params
                                         if isinstance(p, dict)]})
            if made_tabs < 50:      # sanity cap, spec 64
                app.repeater.new_tab(f"{req.method} {target}")
                made_tabs += 1
    title = (spec.get("info") or {}).get("title", "Imported API")
    app.db.kv_set("openapi_catalog", {"title": title, "endpoints": endpoints})
    return {"ok": True, "title": title, "endpoints": endpoints,
            "repeaterTabsCreated": made_tabs}


def import_postman(app, collection: dict) -> dict:
    """Postman v2.x collection → list of HttpRequest drafts (to Repeater)."""
    items = collection.get("item") or []
    out = []
    def walk(lst):
        for it in lst:
            if "item" in it:
                walk(it["item"]); continue
            r = it.get("request") or {}
            url = r.get("url")
            if isinstance(url, dict):
                url = url.get("raw", "")
            if not url:
                continue
            try:
                hdrs = [(h.get("key", "X"), h.get("value", ""))
                        for h in (r.get("header") or [])]
                body = ((r.get("body") or {}).get("raw") or "").encode() \
                    if r.get("body") else None
                req = build_request_from_url(
                    url, r.get("method", "GET"), hdrs, body)
                req.source = "postman-import"
                req.comment = it.get("name", "")
                out.append(req.summary())
                app.db.kv_set("postman_requests",
                              (app.db.kv_get("postman_requests") or [])[:200] +
                              [{"name": it.get("name", ""), "raw":
                                req.raw(origin_form=False).decode(
                                    "utf-8", "replace")}])
            except Exception:
                continue
    walk(items)
    return {"ok": True, "requests": out}


def parse_raw_http(blob: str, *, default_scheme="http",
                   default_host="") -> HttpRequest:
    """Import a raw HTTP request file (Burp-style)."""
    req = HttpRequest.parse(blob.encode("iso-8859-1"),
                            default_scheme=default_scheme,
                            default_host=default_host)
    req.source = "raw-import"
    return req
