"""Analysis modules: decoder, comparer, tech detection, JWT/cookie analysis,
passive security analyzer, rules engine. All pure functions — no network I/O.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import html
import json
import re
import urllib.parse
from typing import Dict, List, Optional

from .http_model import HttpRequest, HttpResponse

# ---------------------------------------------------------------------------
# Decoder (spec 24)
# ---------------------------------------------------------------------------

def _b64url_fix(s: str) -> str:
    s = s.replace("-", "+").replace("_", "/")
    return s + "=" * (-len(s) % 4)


def decode(op: str, data: str) -> str:
    op = op.lower()
    if op == "base64_decode":
        return base64.b64decode(_b64url_fix(data.strip())).decode("utf-8", "replace")
    if op == "base64_encode":
        return base64.b64encode(data.encode()).decode()
    if op == "base32_decode":
        return base64.b32decode(data.strip().upper()).decode("utf-8", "replace")
    if op == "base32_encode":
        return base64.b32encode(data.encode()).decode()
    if op == "url_decode":
        return urllib.parse.unquote_plus(data)
    if op == "url_encode":
        return urllib.parse.quote(data, safe="")
    if op == "html_decode":
        return html.unescape(data)
    if op == "html_encode":
        return html.escape(data)
    if op == "hex_decode":
        return binascii.unhexlify(re.sub(r"\s|0x", "", data)).decode("utf-8", "replace")
    if op == "hex_encode":
        return binascii.hexlify(data.encode()).decode()
    if op == "json_minify":
        return json.dumps(json.loads(data), separators=(",", ":"))
    if op == "json_pretty":
        return json.dumps(json.loads(data), indent=2)
    if op in ("md5", "sha1", "sha256", "sha512"):
        h = hashlib.new(op)
        h.update(data.encode())
        return h.hexdigest()
    if op == "gzip_decompress":
        import gzip as _g
        return _g.decompress(base64.b64decode(_b64url_fix(data.strip()))).decode(
            "utf-8", "replace")
    raise ValueError(f"unknown decode operation '{op}'")


DECODER_OPS = ["base64_encode", "base64_decode", "base32_encode", "base32_decode",
               "url_encode", "url_decode", "html_encode", "html_decode",
               "hex_encode", "hex_decode", "json_pretty", "json_minify",
               "md5", "sha1", "sha256", "sha512"]

# ---------------------------------------------------------------------------
# Comparer (spec 25)
# ---------------------------------------------------------------------------

def compare(a: str, b: str) -> dict:
    """Line-level diff summary + unified diff for the UI."""
    import difflib
    la, lb = a.splitlines(), b.splitlines()
    sm = difflib.SequenceMatcher(None, la, lb)
    ops = []
    added = removed = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            ops.append({"tag": tag, "aStart": i1, "aEnd": i2, "bStart": j1, "bEnd": j2})
        added += j2 - j1 if tag in ("insert", "replace") else 0
        removed += i2 - i1 if tag in ("delete", "replace") else 0
    diff = list(difflib.unified_diff(la, lb, lineterm="", n=2))[:400]
    return {"similarity": round(sm.ratio(), 4), "addedLines": added,
            "removedLines": removed, "changedBlocks": len(ops),
            "diff": "\n".join(diff)}

# ---------------------------------------------------------------------------
# Technology detection (spec 62)
# ---------------------------------------------------------------------------

TECH_SIGNATURES = [
    ("PHP", r"phpsessid|\.php\b|x-powered-by: php"),
    ("ASP.NET", r"asp\.net|__viewstate|x-powered-by: asp\.net|asp\.netsessionid|\baspx?\b"),
    ("Java", r"jsessionid|apache-coyote|x-powered-by: jsf"),
    ("Node.js", r"x-powered-by: express|connect\.sid|io\.socket"),
    ("React", r"data-reactroot|react|_next/static"),
    ("Angular", r"ng-version|angular"),
    ("Vue.js", r"data-v-|vue"),
    ("Django", r"csrftoken|django|x-frame-options.*sameorigin.*django"),
    ("Rails", r"_rails_session|x-rails|turbo"),
    ("WordPress", r"wp-content|wp-includes|wordpress"),
    ("Nginx", r"server: nginx"),
    ("Apache", r"server: apache"),
    ("IIS", r"server: microsoft-iis"),
    ("Cloudflare", r"server: cloudflare|cf-ray"),
    ("GraphQL", r"/graphql|\"query\"\s*:|apollo"),
    ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ"),
    ("Tomcat", r"apache-tomcat|tomcat"),
    ("jQuery", r"jquery"),
    ("Bootstrap", r"bootstrap(?:\.min)?\.css|btn-primary"),
    ("WebSocket", r"upgrade: websocket|websocket"),
]


def detect_technologies(req: HttpRequest, resp: Optional[HttpResponse]) -> List[str]:
    blob_parts = [req.raw().decode("latin1", "replace").lower()]
    if resp:
        # full header list (to_dict collapses duplicate Set-Cookie headers)
        blob_parts.append("\r\n".join(f"{k}: {v}" for k, v in
                                      resp.headers.items()).lower())
        blob_parts.append(resp.text(60_000).lower())
    blob = "\n".join(blob_parts)
    found = []
    for name, pat in TECH_SIGNATURES:
        if re.search(pat, blob, re.I):
            found.append(name)
    return found


# ---------------------------------------------------------------------------
# GraphQL analysis (spec 27)
# ---------------------------------------------------------------------------

_GQL_OP_RE = re.compile(r"\b(query|mutation|subscription)\s*([A-Za-z_]\w*)?\s*"
                        r"(\([^)]*\))?\s*\{", re.I)


def analyze_graphql(req: HttpRequest) -> dict:
    """Detect and structurally parse a GraphQL request (POST JSON body or GET
    ?query=). Returns operations, fields, variables — pure local parsing."""
    out = {"isGraphql": False, "operations": [], "variables": {},
           "operationNames": [], "rawQuery": ""}
    q = dict(req.params())
    body_txt = (req.body or b"").decode("utf-8", "replace")
    query = q.get("query", "")
    op_name = q.get("operationName", "")
    if req.headers.get("Content-Type", "").find("graphql") >= 0 or \
            '"query"' in body_txt[:400] or query:
        try:
            j = json.loads(body_txt) if body_txt.strip().startswith("{") else {}
            query = query or j.get("query", "")
            op_name = op_name or j.get("operationName", "")
            out["variables"] = j.get("variables") or {}
        except Exception:
            pass
    if not query and "graphql" not in req.path.lower():
        return out
    if not query:
        return out
    out["isGraphql"] = True
    out["rawQuery"] = query[:8000]
    for m in _GQL_OP_RE.finditer(query):
        kind, name = m.group(1).lower(), m.group(2) or "(anonymous)"
        vardecl = (m.group(3) or "").strip()
        # top-level selection fields of this operation
        depth, i, fields = 0, m.end() - 1, []
        cur = ""
        while i < len(query):
            c = query[i]
            if c == "{":
                depth += 1
                if depth == 2:
                    cur = ""
            elif c == "}":
                depth -= 1
                if depth == 1 and cur.strip():
                    fields.append(cur.strip().split("(")[0].split(":")[0]
                                  .split()[0] if False else
                                  cur.strip().split("\n")[0].strip()
                                  .split("(")[0].split(":")[0].strip())
                if depth == 0:
                    break
            elif depth == 2 and c in "\r\n":
                t = cur.strip()
                if t:
                    fields.append(t.split("(")[0].split(":")[0].strip())
                cur = ""
            elif depth >= 2:
                cur += c
            i += 1
        out["operations"].append({"type": kind, "name": name,
                                  "variables": vardecl,
                                  "topLevelFields": fields[:40]})
        out["operationNames"].append(name)
    return out

# ---------------------------------------------------------------------------
# JWT analysis (spec 32)
# ---------------------------------------------------------------------------

def analyze_jwt(token: str) -> dict:
    out = {"validStructure": False, "header": None, "payload": None,
           "signaturePresent": False, "observations": [], "expired": None}
    parts = token.strip().split(".")
    if len(parts) < 2:
        out["observations"].append("not a JWT (expected header.payload[.sig])")
        return out
    try:
        header = json.loads(base64.urlsafe_b64decode(_b64url_fix(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(_b64url_fix(parts[1])))
    except Exception as e:
        out["observations"].append(f"base64/json decode failed: {e}")
        return out
    out["validStructure"] = True
    out["header"], out["payload"] = header, payload
    alg = (header.get("alg") or "").upper()
    out["signaturePresent"] = len(parts) == 3 and bool(parts[2])
    import time as _t
    now = _t.time()
    if "exp" in payload:
        out["expired"] = payload["exp"] < now
        if out["expired"]:
            out["observations"].append("token is EXPIRED (exp in past)")
        else:
            out["observations"].append(
                f"expires in {(payload['exp'] - now) / 3600:.1f}h")
    if alg == "NONE" or (alg == "" and not out["signaturePresent"]):
        out["observations"].append("CRITICAL: alg=none / unsigned token accepted? "
                                   "test signature-stripping")
    if alg.startswith("HS"):
        out["observations"].append(
            "symmetric algorithm — test weak-secret brute force & alg-confusion (RS→HS)")
    if header.get("kid") is not None:
        out["observations"].append("'kid' header present — test path traversal / SQLi / "
                                   "JWK injection via kid")
    if header.get("jku") or header.get("x5u"):
        out["observations"].append("URL in header (jku/x5u) — test URL-swallowing attacks")
    for claim in ("sub", "iss", "aud", "iat"):
        if claim in payload:
            pass
    if "scope" in payload or "roles" in payload or "admin" in json.dumps(payload).lower():
        out["observations"].append("authorization claims present — test privilege "
                                   "manipulation (role/scope tampering)")
    return out

# ---------------------------------------------------------------------------
# Cookie analysis (spec 33)
# ---------------------------------------------------------------------------

def analyze_cookies(req: HttpRequest, resp: HttpResponse) -> List[dict]:
    issues: List[dict] = []
    seen: Dict[str, dict] = {}
    for raw in req.headers.get_all("Cookie") if req else []:
        for pair in raw.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                issues.append({"name": k.strip(), "valuePreview": v.strip()[:24],
                               "flags": [], "attrs": {}, "from": "request"})
    for sc in resp.headers.get_all("Set-Cookie") if resp else []:
        attrs = {}
        bits = sc.split(";")
        if "=" in bits[0]:
            name, val = bits[0].split("=", 1)
            attrs["name"] = name.strip()
            attrs["value"] = val.strip()
        for b in bits[1:]:
            bl = b.strip().lower()
            attrs[bl.split("=")[0]] = True
        flags = []
        if "httponly" not in attrs:
            flags.append("missing HttpOnly (JS-readable cookie)")
        if "secure" not in attrs:
            flags.append("missing Secure (sent over plain HTTP)")
        samesite = next((k for k in attrs if k.startswith("samesite")), None)
        if not samesite:
            flags.append("missing SameSite (CSRF exposure)")
        elif "strict" not in str(attrs.get(samesite, "")).lower() and \
                samesite == "samesite":
            flags.append("SameSite=Lax/None — verify CSRF protection")
        val = str(attrs.get("value", ""))
        looks_token = bool(re.search(
            r"(session|sid|token|auth|jwt|bearer)", attrs.get("name", ""), re.I))
        if looks_token and len(val) >= 16 and not (
                "httponly" in attrs and "secure" in attrs):
            flags.append("session-like identifier without full protection")
        issues.append({"name": attrs.get("name", "?"), "flags": flags,
                       "attrs": {k: v for k, v in attrs.items() if v is True},
                       "valuePreview": val[:24] + ("…" if len(val) > 24 else "")})
    return issues

# ---------------------------------------------------------------------------
# Rules engine (spec 51–53): matchers + request/response transform rules
# ---------------------------------------------------------------------------


class RuleEngine:
    """Rules are dicts: {enabled, phase(request|response), match:{field,pattern,regex,status?},
    action:{type:addHeader|removeHeader|setHeader|replaceBody|mark|drop, ...}}"""

    def __init__(self):
        self.rules: List[dict] = []

    def apply(self, phase: str, msg) -> tuple[bool, List[str]]:
        """Mutate msg in place according to enabled rules; return (dropped, log)."""
        logs: List[str] = []
        dropped = False
        for rule in self.rules:
            if not rule.get("enabled", True) or rule.get("phase", "request") != phase:
                continue
            m = rule.get("match", {})
            if not self._matches(m, msg):
                continue
            a = rule.get("action", {})
            t = a.get("type")
            if t == "addHeader":
                msg.headers.add(a["name"], a.get("value", ""))
                logs.append(f"rule[{rule.get('name','')}]: add header {a['name']}")
            elif t == "removeHeader":
                msg.headers.remove(a["name"])
                logs.append(f"rule[{rule.get('name','')}]: remove header {a['name']}")
            elif t == "setHeader":
                msg.headers.set(a["name"], a.get("value", ""))
                logs.append(f"rule[{rule.get('name','')}]: set header {a['name']}")
            elif t == "replaceBody" and phase == "response":
                old, new = a.get("find", ""), a.get("replace", "")
                body = msg.decoded_body()
                if isinstance(body, bytes) and old:
                    nb = body.replace(old.encode(), new.encode())
                    if nb != body:
                        msg.body = nb
                        msg.headers.remove("Content-Length")
                        msg.headers.set("Content-Length", str(len(nb)))
                        logs.append(f"rule[{rule.get('name','')}]: body replace {old!r}")
            elif t == "mark":
                logs.append(f"rule[{rule.get('name','')}]: MARK {a.get('tag','')}")
            elif t == "drop":
                dropped = True
                logs.append(f"rule[{rule.get('name','')}]: DROP")
        return dropped, logs

    @staticmethod
    def _matches(m: dict, msg) -> bool:
        if not m:
            return True
        if "status" in m and isinstance(msg, HttpResponse):
            if msg.status != int(m["status"]):
                return False
        field = m.get("field", "url")
        pattern = m.get("pattern", "")
        regex = m.get("regex", "")
        if field == "url":
            hay = msg.url() if isinstance(msg, HttpRequest) else ""
        elif field == "path":
            hay = msg.path() if isinstance(msg, HttpRequest) else ""
        elif field == "method":
            hay = msg.method if isinstance(msg, HttpRequest) else ""
        elif field == "status":
            hay = str(msg.status) if isinstance(msg, HttpResponse) else ""
        elif field == "body":
            hay = msg.text(200_000) if isinstance(msg, HttpResponse) else \
                msg.body.decode("utf-8", "replace")
        else:  # header:<Name>
            if field.startswith("header:"):
                hay = " ".join(msg.headers.get_all(field.split(":", 1)[1]))
            else:
                hay = ""
        if regex:
            return bool(re.search(regex, hay, re.I))
        if pattern:
            return pattern.lower() in hay.lower()
        return True


# ---------------------------------------------------------------------------
# Passive security analyzer (spec 34)
# ---------------------------------------------------------------------------

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "information": 3}

MISSING_SECURITY_HEADERS = {
    "Content-Security-Policy": ("missing CSP", "medium",
                                "Add a restrictive Content-Security-Policy header."),
    "X-Frame-Options": ("missing X-Frame-Options / frame-ancestors", "low",
                        "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'."),
    "Strict-Transport-Security": ("missing HSTS (HTTPS)", "low",
                                  "Enable Strict-Transport-Security on HTTPS origins."),
    "X-Content-Type-Options": ("missing X-Content-Type-Options: nosniff", "low",
                               "Set nosniff to prevent MIME sniffing."),
    "Referrer-Policy": ("missing Referrer-Policy", "information",
                       "Set a Referrer-Policy to limit referrer leakage."),
}


def fingerprint_key(url: str, status: int, content_type: str, length: int) -> str:
    return hashlib.sha1(f"{url}|{status}|{content_type}|{length}".encode()).hexdigest()[:16]


def passive_analyze(req: HttpRequest, resp: HttpResponse, *,
                    tls: bool = False) -> List[dict]:
    """Return list of finding dicts (deduped upstream by id/fingerprint)."""
    findings: List[dict] = []
    url = req.url()

    def add(sev, title, desc, evidence, rec, conf="firm"):
        key = fingerprint_key(url + req.method, 0, "", 0) + title
        findings.append({
            "id": hashlib.sha1(key.encode()).hexdigest()[:16],
            "severity": sev, "title": title, "description": desc,
            "evidence": evidence[:4000], "url": url, "confidence": conf,
            "recommendation": rec, "source": "passive-analyzer"})

    if resp.status == 0:
        return findings

    hdrs = {k.lower(): v for k, v in resp.headers.items()}

    # --- information disclosure ---------------------------------------
    server = hdrs.get("server", "")
    if re.search(r"\d+\.\d+", server):
        add("low", "Server version disclosure",
            "The Server header exposes product and exact version, aiding targeting "
            "of known CVEs.", f"Server: {server}",
            "Suppress or genericise the Server header.")
    if "x-powered-by" in hdrs:
        add("low", "X-Powered-By disclosure",
            "Technology stack detail leaked to clients.",
            f"X-Powered-By: {hdrs['x-powered-by']}",
            "Remove X-Powered-By.")
    body_l = resp.text(120_000).lower()
    if any(s in body_l for s in ("traceback (most recent call last)",
                                 "warning: php", "stack trace", ".php( on line",
                                 "ora-0", "sqlite3.OperationalError")):
        add("high", "Possible application error / stack trace disclosure",
            "Response contains what appears to be an internal stack trace or "
            "debug output.", resp.text(120_000)[:600],
            "Disable verbose errors in production; return generic error pages.")
    if re.search(r"(BEGIN (RSA|EC|OPENSSH) PRIVATE KEY)", body_l):
        add("high", "Private key material served", "A private key block was found "
            "in the response body.", "", "Rotate the key immediately and remove it.")

    # --- security headers ----------------------------------------------
    for h, (title, sev, rec) in MISSING_SECURITY_HEADERS.items():
        if h.lower() not in hdrs:
            if h == "Strict-Transport-Security" and not tls and req.scheme != "https":
                continue
            add(sev, title, f"The response does not set {h}.",
                "headers: " + "; ".join(sorted(hdrs))[:400], rec, conf="tentative")

    # --- CORS ------------------------------------------------------------
    acao = hdrs.get("access-control-allow-origin", "")
    acac = hdrs.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        add("high", "CORS wildcard with credentials",
            "Access-Control-Allow-Origin: * combined with credentials allows any "
            "site to read authenticated responses (where browsers permit).",
            f"{acao} / {acac}", "Never combine wildcard origin with credentials; "
            "use an explicit allowlist.")
    elif acao.startswith("*") and len(acao) > 1:
        add("medium", "CORS wildcard-subdomain reflection",
            "Loose wildcard subdomain matching may allow attacker-controlled "
            "subdomains.", acao, "Validate origin against an exact allowlist.")
    elif acao and req.headers.get("Origin") and acao == req.headers.get("Origin"):
        add("medium", "CORS reflects arbitrary Origin"
            + (" with credentials" if acac.lower() == "true" else ""),
            "The server echoes the request Origin header back.",
            f"Origin: {req.headers.get('Origin')} → ACAA: {acac}",
            "Use a strict origin allowlist." if acac.lower() == "true"
            else "Confirm reflection is intentional.")

    # --- cookies ---------------------------------------------------------
    for c in analyze_cookies(req, resp):
        for flag in c["flags"]:
            sev = "medium" if ("HttpOnly" in flag or "Secure" in flag) else "low"
            add(sev, f"Cookie '{c['name']}': {flag}",
                "Cookie attribute hygiene problem detected on Set-Cookie.",
                f"{c['name']}={c['valuePreview']}",
                "Set HttpOnly, Secure, SameSite attributes on session cookies.")

    # --- mixed scheme / redirect issues -----------------------------------
    loc = hdrs.get("location", "")
    if resp.status in (301, 302, 303, 307, 308) and loc:
        if loc.startswith("http://") and req.scheme == "https":
            add("medium", "HTTPS→HTTP downgrade redirect",
                "Secure site redirects to plaintext HTTP (SSL-strip vector).",
                f"{resp.status} Location: {loc}",
                "Redirect only to https:// URLs; enable HSTS.")
    # auth basic over http
    if "www-authenticate" in hdrs and "basic" in hdrs["www-authenticate"].lower() \
            and req.scheme != "https":
        add("medium", "HTTP Basic authentication over plaintext",
            "Basic auth prompt served without TLS — credentials travel in base64.",
            hdrs["www-authenticate"], "Serve authentication only over HTTPS.")

    # --- input echo / XSS candidates (confidence=tentative, never auto-active)
    params = req.params()
    echoed = []
    if resp.is_html():
        for name, value in params:
            if len(value) >= 4 and value not in ("null", "undefined") and \
                    value in resp.text(120_000) and html.escape(value) != value:
                echoed.append((name, value))
        for name, value in echoed[:5]:
            add("medium", f"Reflected input in HTML — possible reflected XSS ({name})",
                "Unvalidated user input from the request is echoed into the HTML "
                "response body unescaped. Verify manually with benign probes.",
                f"param {name}={value!r} appears verbatim in response body",
                "Contextually encode all reflected input; deploy CSP.",
                conf="tentative")

    # --- JWT checks --------------------------------------------------------
    authz = req.headers.get("Authorization", "")
    m = re.search(r"Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+[.\w\-]*)", authz)
    if m:
        j = analyze_jwt(m.group(1))
        if j.get("expired"):
            add("low", "Expired JWT still sent by client",
                "The request carries an expired bearer token; check whether the "
                "server still accepts it.", m.group(1)[:80],
                "Ensure servers reject expired tokens.")
        for obs in j["observations"]:
            if "CRITICAL" in obs:
                add("high", "Unsigned/alg=none JWT", obs, m.group(1)[:120],
                    "Reject alg=none and enforce algorithm pinning.")

    # --- sensitive data in GET ---------------------------------------------
    secret_in_query = re.search(
        r"[?&](password|passwd|secret|api[_-]?key|token|access[_-]?key)=([^&#]+)",
        req.target, re.I)
    if secret_in_query:
        add("medium", "Sensitive parameter transmitted in URL query",
            "Secrets in URLs leak via logs, referrers and browser history.",
            secret_in_query.group(0)[:120],
            "Move secrets to POST bodies or headers.")

    # --- directory listing --------------------------------------------------
    if re.search(r'(<title>\s*index of|>parent directory<)', body_l):
        add("medium", "Directory listing enabled",
            "Server returns autoindex directory listings.", body_l[:200],
            "Disable directory listing (Options -Indexes / autoindex off).")

    return findings
