"""Exporters: HAR export, cURL / fetch / Python / Node / PowerShell / raw HTTP
(spec 29-30, 67). Exported text is data only — never auto-executed."""
from __future__ import annotations

import base64
import json
import shlex
import time
import urllib.parse
from typing import Optional

from .http_model import HttpRequest


def _url(req: HttpRequest) -> str:
    return req.url


def to_curl(req: HttpRequest) -> str:
    parts = ["curl", "-X", req.method, shlex.quote(_url(req))]
    for k, v in req.headers.items():
        if k.lower() in ("host", "content-length"):
            continue
        parts += ["-H", shlex.quote(f"{k}: {v}")]
    if req.body:
        try:
            body_txt = req.body.decode("utf-8")
        except UnicodeDecodeError:
            body_txt = req.body.hex()
            parts += ["--data-binary", shlex.quote("@/dev/stdin"),
                      "# (binary body, hex shown)"]
            return " ".join(parts) + "\n" + body_txt
        parts += ["-d", shlex.quote(body_txt)]
    return " ".join(parts)


def to_fetch(req: HttpRequest) -> str:
    headers = {k: v for k, v in req.headers.items()}
    opts = {"method": req.method, "headers": headers}
    if req.body:
        opts["body"] = req.body.decode("utf-8", "replace")
    return (f"fetch({json.dumps(_url(req))}, {json.dumps(opts, indent=2)});"
            .replace("\n", "\n"))


def to_python(req: HttpRequest) -> str:
    lines = ["import requests", "",
             f'url = {json.dumps(_url(req))}',
             f'headers = {json.dumps(dict(req.headers.items()), indent=4)}',
             f'method = {json.dumps(req.method)}']
    if req.body:
        lines.append(f'data = {json.dumps(req.body.decode("utf-8", "replace"))}')
    else:
        lines.append("data = None")
    lines += ["", "resp = requests.request(method, url, headers=headers, "
              "data=data.encode() if isinstance(data, str) else data)",
              "print(resp.status_code, resp.text[:500])"]
    return "\n".join(lines)


def to_node(req: HttpRequest) -> str:
    return to_fetch(req).replace(";", "")   # same shape; usable in Node 18+


def to_powershell(req: HttpRequest) -> str:
    h = "; ".join(f'"@{k}"="{v}"' for k, v in req.headers.items())
    body = ""
    if req.body:
        body = ("\n$body = '" + req.body.decode("utf-8", "replace")
                .replace("'", "''") + "'")
    return (f"$headers = @{{{h}}}{body}\n"
            f'Invoke-WebRequest -Uri "{_url(req)}" -Method {req.method} '
            f"-Headers $headers" + (" -Body $body" if req.body else ""))


def to_raw(req: HttpRequest) -> str:
    return req.raw(origin_form=False).decode("utf-8", "replace")


def export_formats(req: HttpRequest) -> dict:
    return {
        "curl": to_curl(req),
        "fetch": to_fetch(req),
        "python": to_python(req),
        "node": to_node(req),
        "powershell": to_powershell(req),
        "raw": to_raw(req),
    }


# --------------------------------------------------------------------- HAR
def export_har(app, ids: Optional[list] = None) -> dict:
    """Build a HAR 1.1 document from stored history (spec 29)."""
    entries = []
    rows = app.db.list_history(limit=5000)
    for e in rows:
        if ids and e["id"] not in ids:
            continue
        req = app.db.history_request(e["id"])
        if req is None:
            continue
        ent = app.db.get_history_entry(e["id"]) or {}
        resp_raw = bytes(ent.get("response_raw") or b"")
        req_headers = [{"name": k, "value": v} for k, v in req.headers.items()]
        res_headers = []
        status = int(ent.get("status") or 0)
        mime = ent.get("contentType") or ""
        size = int(ent.get("respLen") or 0)
        body_txt = ""
        reason = ""
        if resp_raw:
            from .http_model import HttpResponse
            try:
                r = HttpResponse.parse(resp_raw)
                res_headers = [{"name": k, "value": v}
                               for k, v in r.headers.items()]
                status, reason = r.status, r.reason
                body_txt = r.text(200_000)
                size = len(r.body) or size
                mime = r.content_type() or mime
            except Exception:
                pass
        entries.append({
            "startedDateTime": time.strftime(
                "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(float(ent.get("ts")
                                                             or time.time()))),
            "time": float(ent.get("elapsedMs") or 0),
            "request": {
                "method": req.method, "url": req.url,
                "httpVersion": "HTTP/1.1",
                "headers": req_headers,
                "queryString": [{"name": k, "value": v} for k, v in req.params()],
                "cookies": [], "headersSize": -1, "bodySize": len(req.body or b""),
                **({"postData": {"mimeType": req.headers.get("Content-Type", ""),
                                 "text": (req.body or b"").decode(
                                     "utf-8", "replace")}} if req.body else {}),
            },
            "response": {
                "status": status, "statusText": reason,
                "httpVersion": "HTTP/1.1", "headers": res_headers,
                "cookies": [], "content": {"size": size, "mimeType": mime,
                                           "text": body_txt[:2_000_000]},
                "redirectURL": "", "headersSize": -1, "bodySize": size,
            },
            "cache": {}, "timings": {"send": 1, "wait": float(
                ent.get("elapsedMs") or 1), "receive": 1},
        })
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "OWSI", "version": "1.0"},
            "entries": entries,
        }
    }
