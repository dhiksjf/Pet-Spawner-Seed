"""Project database: SQLite (WAL), migrations, history/sitemap/findings/notes/tags.

All state that must survive restarts lives here: traffic history, findings,
notes, tags, sessions, settings, AI conversations, websocket frames.
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
import uuid
from typing import List, Optional

from .http_model import HttpRequest, HttpResponse

MIGRATIONS = [
    # v1 — core schema
    """
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS history(
      id TEXT PRIMARY KEY, ts REAL, method TEXT, url TEXT, host TEXT, path TEXT,
      scheme TEXT, port INTEGER, status INTEGER, reason TEXT, content_type TEXT,
      req_len INTEGER, resp_len INTEGER, elapsed_ms REAL, source TEXT, comment TEXT,
      tags TEXT, note TEXT, request_raw BLOB, response_raw BLOB, error TEXT,
      tech TEXT, ai_flags TEXT
    );
    CREATE INDEX IF NOT EXISTS hx_host ON history(host);
    CREATE INDEX IF NOT EXISTS hx_ts ON history(ts);
    CREATE TABLE IF NOT EXISTS findings(
      id TEXT PRIMARY KEY, created REAL, updated REAL, severity TEXT, title TEXT,
      description TEXT, evidence TEXT, url TEXT, confidence TEXT, status TEXT,
      source TEXT, recommendation TEXT
    );
    CREATE TABLE IF NOT EXISTS ws_frames(
      id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, ts REAL,
      direction TEXT, opcode TEXT, payload BLOB
    );
    CREATE TABLE IF NOT EXISTS ai_messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT, conv TEXT, ts REAL, role TEXT, content TEXT
    );
    """,
    # v2 — sessions & kv settings
    """
    CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
    """,
]

SCHEMA_VERSION = len(MIGRATIONS)


class ProjectDB:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._migrate()

    def _migrate(self) -> None:
        cur = self._db.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
        row = self._db.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
        ver = int(row[0]) if row else 0
        for i in range(ver, SCHEMA_VERSION):
            self._db.executescript(MIGRATIONS[i])
            ver = i + 1
        self._db.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('schema_version',?)",
                         (str(ver),))
        self._db.commit()

    # ---------------- history -----------------------------------------
    def add_history(self, req: HttpRequest, resp: Optional[HttpResponse], *,
                    tech: str = "", ai_flags: str = "") -> dict:
        entry = {
            "id": req.id, "ts": req.timestamp, "method": req.method, "url": req.url(),
            "host": req.hostname, "path": req.path(), "scheme": req.scheme,
            "port": req.port, "status": resp.status if resp else 0,
            "reason": resp.reason if resp else "",
            "content_type": resp.content_type() if resp else "",
            "req_len": len(req.body),
            "resp_len": len(resp.decoded_body()) if resp else 0,
            "elapsed_ms": resp.elapsed_ms if resp else 0.0,
            "source": req.source, "comment": req.comment, "tags": "[]", "note": "",
            "request_raw": req.raw(), "response_raw": resp.raw() if resp else b"",
            "error": resp.error if resp else "connection failed",
            "tech": tech, "ai_flags": ai_flags,
        }
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO history VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(entry.values()))
            self._db.commit()
        return entry

    def update_history_meta(self, hid: str, *, tags: Optional[List[str]] = None,
                            note: Optional[str] = None,
                            comment: Optional[str] = None) -> None:
        with self._lock:
            if tags is not None:
                self._db.execute("UPDATE history SET tags=? WHERE id=?",
                                 (json.dumps(tags), hid))
            if note is not None:
                self._db.execute("UPDATE history SET note=? WHERE id=?", (note, hid))
            if comment is not None:
                self._db.execute("UPDATE history SET comment=? WHERE id=?",
                                 (comment, hid))
            self._db.commit()

    def get_history_entry(self, hid: str) -> Optional[dict]:
        with self._lock:
            row = self._db.execute("SELECT * FROM history WHERE id=?", (hid,)).fetchone()
        if not row:
            return None
        cols = [d[0] for d in self._db.execute("SELECT * FROM history LIMIT 0").description]
        d = dict(zip(cols, row))
        d["tags"] = json.loads(d.get("tags") or "[]")
        return d

    def history_request(self, hid: str) -> Optional[HttpRequest]:
        e = self.get_history_entry(hid)
        if not e or not e["request_raw"]:
            return None
        try:
            return HttpRequest.parse(bytes(e["request_raw"]),
                                     default_scheme=e["scheme"],
                                     default_host=e["host"], default_port=e["port"])
        except Exception:
            return None

    def list_history(self, *, limit: int = 500, offset: int = 0, host: str = "",
                     search: str = "", min_status: int = 0) -> List[dict]:
        q = ("SELECT id,ts,method,url,host,path,scheme,port,status,content_type,"
             "resp_len,elapsed_ms,source,tags,note,tech,error FROM history")
        conds, args = [], []
        if host:
            conds.append("host=?"); args.append(host)
        if min_status:
            conds.append("status>=?"); args.append(min_status)
        if search:
            conds.append("(url LIKE ? OR CAST(status AS TEXT) LIKE ? OR request_raw LIKE ?)")
            s = f"%{search}%"
            args += [s, s, s]
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        keys = ["id", "ts", "method", "url", "host", "path", "scheme", "port",
                "status", "contentType", "respLen", "elapsedMs", "source", "tags",
                "note", "tech", "error"]
        out = []
        for r in rows:
            d = dict(zip(keys, r))
            d["tags"] = json.loads(d["tags"] or "[]")
            out.append(d)
        return out

    def count_history(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM history").fetchone()[0]

    # ---------------- global search (spec 57) ----------------------------
    def search_all(self, q_text: str, *, regex: bool = False,
                   case_sensitive: bool = False, limit: int = 200) -> dict:
        """Search requests, responses, URLs, headers, findings, notes, AI msgs.
        Plain-text or regex; returns grouped matches with short excerpts."""
        out = {"requests": [], "findings": [], "aiMessages": []}
        if not q_text:
            return out
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            pat = re.compile(q_text if regex else re.escape(q_text), flags)
        except re.error as e:
            raise ValueError(f"invalid regex: {e}")

        def excerpt(s: str):
            m = pat.search(s)
            if not m:
                return None
            a, b = max(0, m.start() - 60), m.end() + 60
            return ("…" if a else "") + s[a:b].replace("\r", "") \
                + ("…" if b < len(s) else "")

        rows = self.list_history(limit=2000)
        n = 0
        for e in rows:
            hay = f"{e['method']} {e['url']} {e.get('note') or ''}"
            ent = self.get_history_entry(e["id"]) or {}
            raws = bytes(ent.get("request_raw") or b"") .decode(
                "utf-8", "replace")
            rawb = bytes(ent.get("response_raw") or b"").decode(
                "utf-8", "replace")
            ex = excerpt(hay) or excerpt(raws) or excerpt(rawb)
            if ex:
                out["requests"].append({"id": e["id"], "method": e["method"],
                                        "url": e["url"], "status": e["status"],
                                        "excerpt": ex})
                n += 1
                if n >= limit:
                    break
        fn = 0
        for f in self.list_findings():
            ex = excerpt(json.dumps({k: v for k, v in f.items()
                                     if k != "evidence"}) +
                         (f.get("evidence") or ""))
            if ex:
                out["findings"].append({**{k: f[k] for k in
                                           ("id", "title", "severity", "url")},
                                        "excerpt": ex})
                fn += 1
                if fn >= 50:
                    break
        with self._lock:
            ai = self._db.execute(
                "SELECT conv, role, content, ts FROM ai_messages "
                "ORDER BY id DESC LIMIT 2000").fetchall()
        an = 0
        for conv, role, content, ts in ai:
            ex = excerpt(content or "")
            if ex:
                out["aiMessages"].append({"conv": conv, "role": role,
                                          "ts": ts, "excerpt": ex})
                an += 1
                if an >= 50:
                    break
        out["total"] = len(out["requests"]) + len(out["findings"]) \
            + len(out["aiMessages"])
        return out

    def delete_history(self, ids: Optional[List[str]] = None, before_ts: float = 0,
                       all_: bool = False) -> int:
        with self._lock:
            if all_:
                n = self._db.execute("DELETE FROM history").rowcount
            elif ids:
                q = f"DELETE FROM history WHERE id IN ({','.join('?'*len(ids))})"
                n = self._db.execute(q, ids).rowcount
            else:
                n = self._db.execute("DELETE FROM history WHERE ts<?",
                                     (before_ts,)).rowcount
            self._db.commit()
        return n

    # ---------------- sitemap ------------------------------------------
    def sitemap(self) -> List[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT host, path, COUNT(*), MAX(status), MIN(ts), MAX(ts)"
                " FROM history GROUP BY host, path ORDER BY host, path").fetchall()
        return [{"host": r[0], "path": r[1], "count": r[2], "lastStatus": r[3],
                 "firstSeen": r[4], "lastSeen": r[5]} for r in rows]

    # ---------------- findings ------------------------------------------
    def add_finding(self, f: dict) -> dict:
        # dedup key (spec 60/137): same title+url updates the existing row so
        # repeated passive passes don't flood the findings table.  The caller's
        # dict is copied first — we must never mutate caller-supplied data or
        # reuse a stale id across different findings.
        f = dict(f)
        with self._lock:
            existing = self._db.execute(
                "SELECT id, created FROM findings WHERE title=? AND url=?",
                (f.get("title", ""), f.get("url", ""))).fetchone()
        if existing:
            # dedup refreshes evidence/metadata but never downgrades the
            # stored severity (passive re-observes must not hide a high risk)
            f["id"] = existing[0]
            f["created"] = existing[1]
            f.setdefault("status", "open")
            f.setdefault("confidence", "tentative")
            f["updated"] = time.time()
        else:
            f.setdefault("id", f"f{uuid.uuid4().hex[:12]}")
            f.setdefault("created", time.time())
            f.setdefault("updated", time.time())
            f.setdefault("status", "open")
            f.setdefault("confidence", "tentative")
            f.setdefault("severity", "information")
        sev_rank = {"information": 0, "low": 1, "medium": 2, "high": 3,
                    "critical": 4}
        with self._lock:
            if existing:
                cur = self._db.execute(
                    "SELECT severity FROM findings WHERE id=?",
                    (f["id"],)).fetchone()
                if cur and sev_rank.get(cur[0], 0) > sev_rank.get(
                        f.get("severity", "information"), 0):
                    f["severity"] = cur[0]
            self._db.execute(
                "INSERT OR REPLACE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (f["id"], f["created"], f["updated"], f.get("severity", "information"),
                 f.get("title", ""), f.get("description", ""), f.get("evidence", ""),
                 f.get("url", ""), f["confidence"], f["status"],
                 f.get("source", "analyzer"), f.get("recommendation", "")))
            self._db.commit()
        return f

    def list_findings(self) -> List[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id,created,updated,severity,title,description,evidence,url,"
                "confidence,status,source,recommendation FROM findings"
                " ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1"
                " WHEN 'low' THEN 2 ELSE 3 END, created").fetchall()
        keys = ["id", "created", "updated", "severity", "title", "description",
                "evidence", "url", "confidence", "status", "source", "recommendation"]
        return [dict(zip(keys, r)) for r in rows]

    def set_finding_status(self, fid: str, status: str) -> bool:
        with self._lock:
            n = self._db.execute("UPDATE findings SET status=?, updated=? WHERE id=?",
                                 (status, time.time(), fid)).rowcount
            self._db.commit()
        return bool(n)

    def finding_exists(self, key: str) -> bool:
        with self._lock:
            return bool(self._db.execute(
                "SELECT 1 FROM findings WHERE id=? LIMIT 1", (key,)).fetchone())

    # ---------------- websocket frames ----------------------------------
    def add_ws_frame(self, session_id: str, direction: str, opcode: str,
                     payload: bytes) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO ws_frames(session_id,ts,direction,opcode,payload)"
                " VALUES(?,?,?,?,?)",
                (session_id, time.time(), direction, opcode, payload[:65536]))
            self._db.commit()

    def list_ws_sessions(self) -> List[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT session_id, COUNT(*), MIN(ts), MAX(ts) FROM ws_frames"
                " GROUP BY session_id ORDER BY MAX(ts) DESC").fetchall()
        return [{"sessionId": r[0], "frames": r[1], "started": r[2], "last": r[3]}
                for r in rows]

    def ws_frames(self, session_id: str, limit: int = 500) -> List[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT ts,direction,opcode,payload FROM ws_frames WHERE session_id=?"
                " ORDER BY id DESC LIMIT ?", (session_id, limit)).fetchall()
        return [{"ts": r[0], "direction": r[1], "opcode": r[2],
                 "payload": bytes(r[3]).decode("utf-8", "replace")} for r in reversed(rows)]

    # ---------------- AI conversation ------------------------------------
    def add_ai_message(self, conv: str, role: str, content: str) -> None:
        with self._lock:
            self._db.execute("INSERT INTO ai_messages(conv,ts,role,content)"
                             " VALUES(?,?,?,?)", (conv, time.time(), role, content))
            self._db.commit()

    def ai_history(self, conv: str, limit: int = 40) -> List[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT ts,role,content FROM ai_messages WHERE conv=?"
                " ORDER BY id DESC LIMIT ?", (conv, limit)).fetchall()
        return [{"ts": r[0], "role": r[1], "content": r[2]} for r in reversed(rows)]

    # ---------------- kv ---------------------------------------------------
    def kv_set(self, k: str, v) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)",
                             (k, json.dumps(v)))
            self._db.commit()

    def kv_get(self, k: str, default=None):
        with self._lock:
            row = self._db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return json.loads(row[0]) if row else default

    def close(self) -> None:
        with self._lock:
            self._db.close()
