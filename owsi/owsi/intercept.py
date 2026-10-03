"""Intercept engine: pause requests AND responses for live editing.

The proxy hands each message to Interceptor.put_request(); if interception is
on, the worker thread blocks until the UI (dashboard or browser extension)
forwards / drops / a mutated version. Drop returns a synthetic 508 response
to the browser so nothing leaks upstream.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional

from .http_model import HttpRequest, HttpResponse


@dataclass
class InterceptedItem:
    kind: str                    # "request" | "response"
    id: str
    request: Optional[HttpRequest] = None
    response: Optional[HttpResponse] = None
    _event: threading.Event = field(default_factory=threading.Event)
    action: str = ""             # forward | drop
    mutated_request: Optional[HttpRequest] = None
    mutated_response: Optional[HttpResponse] = None
    arrived: float = field(default_factory=time.time)

    def wait(self, timeout: float) -> "InterceptedItem":
        self._event.wait(timeout)
        return self


class Interceptor:
    def __init__(self):
        self.lock = threading.Lock()
        # Off by default: with interception ON every proxied request blocks the
        # worker thread until the UI forwards/drops it (up to timeout_sec).
        # That is only usable when a dashboard is actually watching; the proxy
        # must pass traffic transparently otherwise. Toggle via
        # POST /api/intercept/flags or the dashboard Intercept tab.
        self.intercept_requests = False
        self.intercept_responses = False
        self.timeout_sec = 300.0
        self._queue: List[InterceptedItem] = []
        self._by_id: dict = {}

    def set_flags(self, req: Optional[bool] = None, resp: Optional[bool] = None,
                  timeout: Optional[float] = None) -> None:
        with self.lock:
            if req is not None:
                self.intercept_requests = req
            if resp is not None:
                self.intercept_responses = resp
            if timeout is not None:
                self.timeout_sec = timeout

    def state(self) -> dict:
        with self.lock:
            return {"interceptRequests": self.intercept_requests,
                    "interceptResponses": self.intercept_responses,
                    "pending": [self._describe(i) for i in self._queue],
                    "timeoutSec": self.timeout_sec}

    def _describe(self, item: InterceptedItem) -> dict:
        d = {"id": item.id, "kind": item.kind, "arrived": item.arrived}
        if item.request:
            d["request"] = item.request.summary()
            d["requestRaw"] = item.request.raw().decode("utf-8", "replace")[:200_000]
        if item.response:
            d["response"] = item.response.summary()
            d["responseRaw"] = item.response.raw().decode("utf-8", "replace")[:200_000]
        return d

    # ------------------------------------------------------------------
    def intercept_request(self, req: HttpRequest) -> tuple[str, Optional[HttpRequest]]:
        """Block until user acts. Returns ('forward', maybe-mutated) or 'drop'."""
        with self.lock:
            if not self.intercept_requests:
                return "forward", req
            item = InterceptedItem(kind="request", id=req.id, request=req)
            self._queue.append(item)
            self._by_id[req.id] = item
        self.on_pending and self.on_pending(item)
        item.wait(self.timeout_sec)
        with self.lock:
            if item in self._queue:
                self._queue.remove(item)
            self._by_id.pop(req.id, None)
        if item.action == "drop":
            return "drop", None
        if item.action == "forward" and item.mutated_request:
            return "forward", item.mutated_request
        return "forward", req          # timeout → auto-forward (fail open on traffic,
                                       # never silently drop user browsing)

    def intercept_response(self, req: HttpRequest, resp: HttpResponse) \
            -> tuple[str, Optional[HttpResponse]]:
        with self.lock:
            if not self.intercept_responses:
                return "forward", resp
            resp_id = f"r{req.id}"
            item = InterceptedItem(kind="response", id=resp_id,
                                   request=req, response=resp)
            self._queue.append(item)
            self._by_id[resp_id] = item
        self.on_pending and self.on_pending(item)
        item.wait(self.timeout_sec)
        with self.lock:
            if item in self._queue:
                self._queue.remove(item)
            self._by_id.pop(resp_id, None)
        if item.action == "drop":
            return "drop", None
        if item.action == "forward" and item.mutated_response:
            return "forward", item.mutated_response
        return "forward", resp

    # callback installed by control server to push 'intercept.pending' events
    on_pending = None

    # ------------------------------------------------------------------
    def resolve(self, iid: str, action: str, raw_message: str = "",
                parse_ctx: Optional[dict] = None) -> bool:
        with self.lock:
            item = self._by_id.get(iid)
        if not item:
            return False
        if action == "forward" and raw_message:
            try:
                if item.kind == "request":
                    ctx = parse_ctx or {}
                    item.mutated_request = HttpRequest.parse(
                        raw_message.encode("iso-8859-1"),
                        default_scheme=ctx.get("scheme", item.request.scheme),
                        default_host=ctx.get("host", item.request.host),
                        default_port=ctx.get("port", item.request.port))
                else:
                    item.mutated_response = HttpResponse.parse(
                        raw_message.encode("iso-8859-1"))
            except Exception as e:
                item.action = "drop"
                item._event.set()
                raise ValueError(f"could not parse edited message: {e}")
        item.action = action
        item._event.set()
        return True

    def pending(self) -> List[dict]:
        with self.lock:
            return [self._describe(i) for i in self._queue]
