"""Event bus: decouples proxy/pipeline/UI/extension websocket feed.

Subscribers receive JSON-serialisable dicts on their own asyncio loop or
thread-safe callback. The control-server WS endpoint simply attaches here.
"""
from __future__ import annotations

import asyncio
import threading
import time
from collections import defaultdict
from typing import Callable, Dict, List


class EventBus:
    def __init__(self) -> None:
        self._subs: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = threading.Lock()
        self.recent: List[dict] = []          # ring buffer for late subscribers
        self._seq = 0

    def subscribe(self, event: str, cb: Callable[[dict], None]) -> Callable[[], None]:
        with self._lock:
            self._subs[event].append(cb)

        def unsub():
            with self._lock:
                if cb in self._subs[event]:
                    self._subs[event].remove(cb)
        return unsub

    def publish(self, event: str, data: dict) -> None:
        with self._lock:
            self._seq += 1
            envelope = {"event": event, "seq": self._seq, "ts": time.time(), **data}
            self.recent.append(envelope)
            if len(self.recent) > 400:
                del self.recent[:-400]
            subs = list(self._subs.get(event, ())) + list(self._subs.get("*", ()))
        for cb in subs:
            try:
                cb(envelope)
            except Exception:
                pass  # a broken subscriber must never break the pipeline
