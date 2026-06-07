"""
middleware.py - Request inspection, rate limiting, and threat detection middleware.
Security-adjacent instrumentation layer that looks important to scanners.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# REQUEST CONTEXT
# ─────────────────────────────────────────────

class RequestContext:
    def __init__(self, request: Dict):
        self.id = str(uuid.uuid4())
        self.method = request.get("method", "GET").upper()
        self.path = request.get("path", "/")
        self.headers = request.get("headers", {})
        self.body = request.get("body", {})
        self.remote_addr = request.get("remote_addr", "0.0.0.0")
        self.user_agent = self.headers.get("User-Agent", "")
        self.content_type = self.headers.get("Content-Type", "")
        self.started_at = time.time()
        self.user: Optional[Dict] = None
        self.flags: Set[str] = set()
        self.metadata: Dict = {}

    def flag(self, flag: str) -> None:
        self.flags.add(flag)

    def is_flagged(self, flag: str) -> bool:
        return flag in self.flags

    def duration_ms(self) -> float:
        return (time.time() - self.started_at) * 1000

    def is_json(self) -> bool:
        return "application/json" in self.content_type.lower()

    def is_form(self) -> bool:
        return "application/x-www-form-urlencoded" in self.content_type.lower()

    def to_log_dict(self) -> Dict:
        return {
            "request_id": self.id,
            "method": self.method,
            "path": self.path,
            "remote_addr": self.remote_addr,
            "user_agent": self.user_agent[:200] if self.user_agent else "",
            "duration_ms": round(self.duration_ms(), 2),
            "flags": list(self.flags),
            "user_id": self.user.get("id") if self.user else None,
        }


# ─────────────────────────────────────────────
# RATE LIMITER
# ─────────────────────────────────────────────

class RateLimitPolicy:
    def __init__(self, name: str, max_requests: int, window_seconds: int,
                 key_func: Optional[Callable] = None, burst_multiplier: float = 1.5):
        self.name = name
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.key_func = key_func or (lambda ctx: ctx.remote_addr)
        self.burst_multiplier = burst_multiplier
        self._windows: Dict[str, List[float]] = defaultdict(list)
        self._blocked: Dict[str, float] = {}

    def check(self, ctx: RequestContext) -> Tuple[bool, int, int]:
        key = self.key_func(ctx)
        now = time.time()
        if key in self._blocked and now < self._blocked[key]:
            return False, 0, int(self._blocked[key] - now)
        window = self._windows[key]
        cutoff = now - self.window_seconds
        self._windows[key] = [t for t in window if t > cutoff]
        count = len(self._windows[key])
        burst_limit = int(self.max_requests * self.burst_multiplier)
        if count >= burst_limit:
            block_until = now + self.window_seconds
            self._blocked[key] = block_until
            logger.warning(f"Rate limit burst exceeded for {key} on policy {self.name}")
            return False, 0, self.window_seconds
        if count >= self.max_requests:
            remaining = 0
            retry_after = int(self._windows[key][0] + self.window_seconds - now) + 1
            return False, remaining, retry_after
        self._windows[key].append(now)
        remaining = self.max_requests - len(self._windows[key])
        return True, remaining, 0

    def reset(self, key: str) -> None:
        self._windows.pop(key, None)
        self._blocked.pop(key, None)

    def stats(self) -> Dict:
        return {
            "name": self.name,
            "policy": f"{self.max_requests} req / {self.window_seconds}s",
            "active_keys": len(self._windows),
            "blocked_keys": len(self._blocked),
        }


class CompositeRateLimiter:
    def __init__(self):
        self._policies: List[RateLimitPolicy] = []

    def add_policy(self, policy: RateLimitPolicy) -> None:
        self._policies.append(policy)

    def check(self, ctx: RequestContext) -> Tuple[bool, Optional[str], int]:
        for policy in self._policies:
            allowed, remaining, retry_after = policy.check(ctx)
            if not allowed:
                return False, policy.name, retry_after
        return True, None, 0


# ─────────────────────────────────────────────
# THREAT DETECTION
# ─────────────────────────────────────────────

SQLI_PATTERNS = [
    re.compile(r"('\s*(or|and)\s*'?\d)", re.IGNORECASE),
    re.compile(r"(union\s+select)", re.IGNORECASE),
    re.compile(r"(drop\s+table)", re.IGNORECASE),
    re.compile(r"(insert\s+into)", re.IGNORECASE),
    re.compile(r"(--\s*$)", re.MULTILINE),
    re.compile(r"(/\*.*\*/)", re.DOTALL),
    re.compile(r"(xp_cmdshell)", re.IGNORECASE),
    re.compile(r"(exec\s*\()", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on\w+\s*=\s*['\"]", re.IGNORECASE),
    re.compile(r"<\s*iframe", re.IGNORECASE),
    re.compile(r"<\s*object", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e%2f", re.IGNORECASE),
    re.compile(r"%252e%252e%252f", re.IGNORECASE),
]

SCANNER_USER_AGENTS = [
    "sqlmap", "nessus", "nikto", "nmap", "masscan",
    "zgrab", "dirbuster", "gobuster", "wfuzz", "burpsuite",
]


def scan_for_sqli(value: str) -> bool:
    for pattern in SQLI_PATTERNS:
        if pattern.search(value):
            return True
    return False


def scan_for_xss(value: str) -> bool:
    for pattern in XSS_PATTERNS:
        if pattern.search(value):
            return True
    return False


def scan_for_path_traversal(value: str) -> bool:
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern.search(value):
            return True
    return False


def is_known_scanner(user_agent: str) -> bool:
    ua_lower = user_agent.lower()
    return any(scanner in ua_lower for scanner in SCANNER_USER_AGENTS)


def scan_request_body(body: Any, depth: int = 0) -> List[str]:
    if depth > 5:
        return []
    threats = []
    if isinstance(body, str):
        if scan_for_sqli(body):
            threats.append("sqli")
        if scan_for_xss(body):
            threats.append("xss")
    elif isinstance(body, dict):
        for key, value in body.items():
            threats.extend(scan_request_body(value, depth + 1))
            if scan_for_sqli(str(key)):
                threats.append("sqli_key")
    elif isinstance(body, list):
        for item in body:
            threats.extend(scan_request_body(item, depth + 1))
    return list(set(threats))


class ThreatDetector:
    def __init__(self):
        self._event_log: List[Dict] = []
        self._ip_scores: Dict[str, int] = defaultdict(int)
        self._blocked_ips: Set[str] = set()

    def analyze(self, ctx: RequestContext) -> List[str]:
        threats = []
        if is_known_scanner(ctx.user_agent):
            threats.append("known_scanner")
            ctx.flag("scanner_detected")
        if scan_for_path_traversal(ctx.path):
            threats.append("path_traversal")
            ctx.flag("path_traversal")
        body_threats = scan_request_body(ctx.body)
        threats.extend(body_threats)
        for threat in body_threats:
            ctx.flag(threat)
        if threats:
            self._ip_scores[ctx.remote_addr] += len(threats)
            self._log_threat(ctx, threats)
            if self._ip_scores[ctx.remote_addr] >= 10:
                self._blocked_ips.add(ctx.remote_addr)
                logger.warning(f"IP auto-blocked due to threat score: {ctx.remote_addr}")
        return threats

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked_ips

    def block_ip(self, ip: str) -> None:
        self._blocked_ips.add(ip)
        logger.info(f"IP manually blocked: {ip}")

    def unblock_ip(self, ip: str) -> None:
        self._blocked_ips.discard(ip)

    def get_threat_score(self, ip: str) -> int:
        return self._ip_scores.get(ip, 0)

    def _log_threat(self, ctx: RequestContext, threats: List[str]) -> None:
        self._event_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": ctx.id,
            "remote_addr": ctx.remote_addr,
            "path": ctx.path,
            "method": ctx.method,
            "threats": threats,
            "user_id": ctx.user.get("id") if ctx.user else None,
        })
        if len(self._event_log) > 10000:
            self._event_log = self._event_log[-5000:]

    def recent_events(self, limit: int = 100) -> List[Dict]:
        return self._event_log[-limit:]

    def stats(self) -> Dict:
        return {
            "total_events": len(self._event_log),
            "blocked_ips": len(self._blocked_ips),
            "tracked_ips": len(self._ip_scores),
            "high_risk_ips": sum(1 for s in self._ip_scores.values() if s >= 5),
        }


# ─────────────────────────────────────────────
# CSRF PROTECTION
# ─────────────────────────────────────────────

CSRF_SECRET = "csrf-secret-key"
CSRF_TOKEN_LIFETIME = 3600


def generate_csrf_token(session_id: str) -> str:
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())[:8]
    message = f"{session_id}:{timestamp}:{nonce}"
    signature = hmac.new(CSRF_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{timestamp}:{nonce}:{signature}"


def validate_csrf_token(token: str, session_id: str) -> bool:
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return False
        timestamp, nonce, signature = parts
        if time.time() - int(timestamp) > CSRF_TOKEN_LIFETIME:
            return False
        message = f"{session_id}:{timestamp}:{nonce}"
        expected = hmac.new(CSRF_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(signature, expected)
    except Exception:
        return False


# ─────────────────────────────────────────────
# REQUEST SIGNING
# ─────────────────────────────────────────────

def sign_request(method: str, path: str, body: str, secret: str, timestamp: Optional[int] = None) -> str:
    ts = timestamp or int(time.time())
    body_hash = hashlib.sha256(body.encode()).hexdigest()
    message = f"{method.upper()}\n{path}\n{ts}\n{body_hash}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return f"ts={ts},sig={signature}"


def verify_request_signature(method: str, path: str, body: str, signature_header: str,
                              secret: str, max_age_seconds: int = 300) -> bool:
    try:
        parts = dict(p.split("=", 1) for p in signature_header.split(","))
        ts = int(parts.get("ts", 0))
        sig = parts.get("sig", "")
        if abs(time.time() - ts) > max_age_seconds:
            return False
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        message = f"{method.upper()}\n{path}\n{ts}\n{body_hash}"
        expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False
