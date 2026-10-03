"""Security Test Policy (spec section 5) — central authorization gate.

Modes: PASSIVE / MANUAL_ACTIVE / AUTHORIZED / LAB / plus dangerous-action
confirmation. Every active module (repeater, fuzzer, scanner, AI actions)
must call policy.check(...) before touching the network.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit

MODES = ("PASSIVE", "MANUAL_ACTIVE", "AUTHORIZED", "LAB")

DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH", "POST"}


@dataclass
class PolicyLimits:
    request_rate_per_sec: float = 10.0
    max_concurrency: int = 8
    max_requests_per_job: int = 5_000
    max_body_size: int = 2 * 1024 * 1024          # 2 MiB outbound body
    max_response_size: int = 32 * 1024 * 1024     # 32 MiB inbound
    timeout_sec: float = 20.0
    max_job_duration_sec: float = 600.0


@dataclass
class TargetScope:
    allowed_hosts: List[str] = field(default_factory=list)   # patterns or exact
    allowed_ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8443])
    allowed_schemes: List[str] = field(default_factory=lambda: ["http", "https"])
    allowed_paths: List[str] = field(default_factory=list)   # empty = all
    excluded_hosts: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)


def _is_private_host(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


class RateLimiter:
    def __init__(self, rate_per_sec: float):
        self.rate = max(0.1, rate_per_sec)
        self._tokens = self.rate
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def set_rate(self, rate_per_sec: float) -> None:
        with self._lock:
            self.rate = max(0.1, rate_per_sec)
            self._tokens = min(self._tokens, self.rate)

    def acquire(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.rate, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return True
            if time.monotonic() > deadline:
                return False
            time.sleep(0.05)


class SecurityPolicy:
    """Central gate consulted by every network-touching subsystem."""

    def __init__(self, mode: str = "LAB", scope: Optional[TargetScope] = None,
                 limits: Optional[PolicyLimits] = None):
        self.lock = threading.RLock()
        self.mode = mode if mode in MODES else "LAB"
        self.scope = scope or TargetScope()
        self.limits = limits or PolicyLimits()
        self.require_confirmation_for_dangerous = True
        self.approved_actions: set = set()      # action ids user explicitly approved
        self._limiter = RateLimiter(self.limits.request_rate_per_sec)
        self.activity_log: List[dict] = []

    # ------------------------------------------------------------------
    def set_mode(self, mode: str) -> None:
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode}")
        with self.lock:
            self.mode = mode
            self._log_event("mode_changed", {"mode": mode})

    def to_dict(self) -> dict:
        with self.lock:
            return {
                "mode": self.mode,
                "scope": {
                    "allowedHosts": self.scope.allowed_hosts,
                    "allowedPorts": self.scope.allowed_ports,
                    "allowedSchemes": self.scope.allowed_schemes,
                    "allowedPaths": self.scope.allowed_paths,
                    "excludedHosts": self.scope.excluded_hosts,
                    "excludedPaths": self.scope.excluded_paths,
                },
                "limits": {
                    "requestRatePerSec": self.limits.request_rate_per_sec,
                    "maxConcurrency": self.limits.max_concurrency,
                    "maxRequestsPerJob": self.limits.max_requests_per_job,
                    "maxBodySize": self.limits.max_body_size,
                    "maxResponseSize": self.limits.max_response_size,
                    "timeoutSec": self.limits.timeout_sec,
                    "maxJobDurationSec": self.limits.max_job_duration_sec,
                },
                "requireConfirmationForDangerous": self.require_confirmation_for_dangerous,
            }

    def update(self, data: dict) -> None:
        with self.lock:
            if "mode" in data:
                self.set_mode(data["mode"])
            sc = data.get("scope")
            if sc:
                for k_remote, k_attr in (("allowedHosts", "allowed_hosts"),
                                         ("allowedPorts", "allowed_ports"),
                                         ("allowedSchemes", "allowed_schemes"),
                                         ("allowedPaths", "allowed_paths"),
                                         ("excludedHosts", "excluded_hosts"),
                                         ("excludedPaths", "excluded_paths")):
                    if k_remote in sc:
                        setattr(self.scope, k_attr, list(sc[k_remote]))
            lim = data.get("limits")
            if lim:
                m = {"requestRatePerSec": "request_rate_per_sec",
                     "maxConcurrency": "max_concurrency",
                     "maxRequestsPerJob": "max_requests_per_job",
                     "maxBodySize": "max_body_size",
                     "maxResponseSize": "max_response_size",
                     "timeoutSec": "timeout_sec",
                     "maxJobDurationSec": "max_job_duration_sec"}
                for k_remote, k_attr in m.items():
                    if k_remote in lim:
                        setattr(self.limits, k_attr, lim[k_remote])
                self._limiter.set_rate(self.limits.request_rate_per_sec)
            if "requireConfirmationForDangerous" in data:
                self.require_confirmation_for_dangerous = bool(
                    data["requireConfirmationForDangerous"])

    # ------------------------------------------------------------------
    def host_in_scope(self, host: str) -> bool:
        h = host.lower()
        for pat in self.scope.excluded_hosts:
            if fnmatch.fnmatch(h, pat.lower()) or h == pat.lower():
                return False
        if self.mode == "LAB":
            # LAB: private/loopback auto-allowed; others need explicit allowlist
            if _is_private_host(h):
                return True
        if self.mode in ("PASSIVE", "MANUAL_ACTIVE"):
            # default-deny for active work unless explicitly listed
            pass
        for pat in self.scope.allowed_hosts:
            p = pat.lower()
            if h == p or fnmatch.fnmatch(h, p):
                return True
            # "*.example.com" also matches the bare apex "example.com"
            if (p.startswith("*.") and h == p[2:]) or \
               (p.startswith("*") and h.endswith(p[1:])):
                return True
        return False

    def target_allowed(self, scheme: str, host: str, port: int, path: str = "/") -> \
            tuple[bool, str]:
        # tolerate callers passing a "host:port" string or an empty host
        if host and ":" in host and not host.startswith("["):
            host_only, _, p = host.rpartition(":")
            try:
                port = int(p)
            except ValueError:
                pass
            host = host_only
        host = host or ""
        if scheme not in self.scope.allowed_schemes:
            return False, f"scheme '{scheme}' not allowed"
        if port not in self.scope.allowed_ports:
            return False, f"port {port} not allowed"
        # LAB mode auto-allows loopback/private targets even with an empty
        # allowlist (spec section 5 MODE 4); other modes stay default-deny.
        lab_auto = (self.mode == "LAB" and _is_private_host(host))
        if not lab_auto and not self.host_in_scope(host):
            return False, f"host '{host}' outside target scope (mode={self.mode})"
        for p in self.scope.excluded_paths:
            if fnmatch.fnmatch(path, p):
                return False, f"path '{path}' excluded"
        if self.scope.allowed_paths:
            if not any(fnmatch.fnmatch(path, p) for p in self.scope.allowed_paths):
                return False, f"path '{path}' not inside allowed paths"
        return True, ""

    # ------------------------------------------------------------------
    def check_active_send(self, method: str, scheme: str, host: str, port: int,
                          path: str = "/", *, origin: str = "manual",
                          action_id: Optional[str] = None,
                          dangerous: bool = False) -> None:
        """Raise PermissionError if the send is not permitted right now.

        PASSIVE blocks ALL active sends. MANUAL_ACTIVE allows user-initiated
        sends to in-scope hosts. AUTHORIZED/LAB additionally allow automated
        modules (fuzzer/scanner/AI) within scope+limits.
        """
        with self.lock:
            ok, why = self.target_allowed(scheme, host, port, path)
            if not ok:
                raise PermissionError(f"blocked by Security Test Policy: {why}")
            if self.mode == "PASSIVE":
                raise PermissionError(
                    "blocked: policy mode PASSIVE does not permit sending requests; "
                    "switch to MANUAL_ACTIVE / AUTHORIZED / LAB")
            is_dangerous = dangerous or method.upper() in DANGEROUS_METHODS \
                           or origin in ("fuzzer", "scanner", "ai")
            if self.require_confirmation_for_dangerous and is_dangerous \
                    and origin != "manual":
                # automated dangerous actions require an explicit approval token
                if not action_id or action_id not in self.approved_actions:
                    raise PermissionError(
                        "blocked: automated/dangerous action requires explicit user "
                        "approval (approve the pending action first)")
                self.approved_actions.discard(action_id)  # single use

    def approve_action(self, action_id: str) -> None:
        with self.lock:
            self.approved_actions.add(action_id)

    def wait_rate(self, timeout: float = 30.0) -> bool:
        return self._limiter.acquire(timeout)

    # ------------------------------------------------------------------
    def _log_event(self, kind: str, data: dict) -> None:
        self.activity_log.append({"t": time.time(), "kind": kind, **data})
        if len(self.activity_log) > 2000:
            del self.activity_log[:-2000]

    def log_send(self, scheme, host, port, path, origin, result) -> None:
        self._log_event("send", {"target": f"{scheme}://{host}:{port}{path}",
                                 "origin": origin, "result": result})
