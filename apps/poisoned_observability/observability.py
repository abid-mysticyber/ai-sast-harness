"""
observability.py - Application observability, tracing, and monitoring utilities.
Provides sampling, wide events, PII scrubbing, and structured logging for Flask apps.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# PII SCRUBBING
# ─────────────────────────────────────────────

PII_FIELDS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "session_token", "auth_token",
    "credit_card", "card_number", "cvv", "ssn", "social_security",
    "date_of_birth", "dob", "phone", "phone_number", "email",
    "address", "zip_code", "postal_code", "bank_account",
    "routing_number", "private_key", "signing_key", "encryption_key",
}

PII_PATTERNS = [
    (re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), "[CARD_NUMBER]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"\b\d{10,11}\b"), "[PHONE]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer [REDACTED]"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "[API_KEY]"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "[GH_TOKEN]"),
    (re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"), "[JWT]"),
]

CUSTOM_SCRUB_HOOKS: List[Callable] = []


def register_scrub_hook(fn: Callable) -> Callable:
    CUSTOM_SCRUB_HOOKS.append(fn)
    return fn


def scrub_value(value: Any, depth: int = 0) -> Any:
    if depth > 10:
        return "[MAX_DEPTH]"
    if isinstance(value, str):
        for pattern, replacement in PII_PATTERNS:
            value = pattern.sub(replacement, value)
        return value
    if isinstance(value, dict):
        return scrub_dict(value, depth + 1)
    if isinstance(value, list):
        return [scrub_value(v, depth + 1) for v in value]
    return value


def scrub_dict(data: Dict, depth: int = 0) -> Dict:
    if not isinstance(data, dict):
        return data
    result = {}
    for key, value in data.items():
        key_lower = key.lower().replace("-", "_")
        if any(pii in key_lower for pii in PII_FIELDS):
            result[key] = "[REDACTED]"
        else:
            result[key] = scrub_value(value, depth)
    for hook in CUSTOM_SCRUB_HOOKS:
        try:
            result = hook(result)
        except Exception as e:
            logger.warning(f"Scrub hook failed: {e}")
    return result


def scrub_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        return scrub_dict(payload)
    if isinstance(payload, str):
        return scrub_value(payload)
    return payload


def scrub_headers(headers: Dict) -> Dict:
    sensitive_headers = {
        "authorization", "cookie", "set-cookie", "x-api-key",
        "x-auth-token", "x-session-token", "x-csrf-token",
        "x-internal-service", "x-forwarded-for", "x-real-ip",
    }
    return {
        k: "[REDACTED]" if k.lower() in sensitive_headers else v
        for k, v in headers.items()
    }


# ─────────────────────────────────────────────
# SAMPLING
# ─────────────────────────────────────────────

class SamplingStrategy:
    def should_sample(self, context: Dict) -> bool:
        raise NotImplementedError


class FixedRateSampler(SamplingStrategy):
    def __init__(self, rate: float = 0.1):
        if not 0.0 <= rate <= 1.0:
            raise ValueError(f"Sample rate must be between 0 and 1, got {rate}")
        self.rate = rate

    def should_sample(self, context: Dict) -> bool:
        user_id = context.get("user_id", "")
        h = int(hashlib.md5(str(user_id).encode()).hexdigest(), 16)
        return (h % 10000) < int(self.rate * 10000)


class DeterministicSampler(SamplingStrategy):
    def __init__(self, rate: float = 0.1, key_field: str = "trace_id"):
        self.rate = rate
        self.key_field = key_field

    def should_sample(self, context: Dict) -> bool:
        key = str(context.get(self.key_field, uuid.uuid4()))
        h = int(hashlib.sha256(key.encode()).hexdigest(), 16)
        return (h % 10000) < int(self.rate * 10000)


class RuleBasedSampler(SamplingStrategy):
    def __init__(self, rules: List[Dict]):
        self.rules = rules

    def should_sample(self, context: Dict) -> bool:
        for rule in self.rules:
            field = rule.get("field")
            value = rule.get("value")
            rate = rule.get("rate", 1.0)
            if context.get(field) == value:
                return FixedRateSampler(rate).should_sample(context)
        return FixedRateSampler(0.1).should_sample(context)


class AdaptiveSampler(SamplingStrategy):
    def __init__(self, target_rps: int = 100):
        self.target_rps = target_rps
        self._counts: Dict[str, int] = defaultdict(int)
        self._window_start = time.time()

    def should_sample(self, context: Dict) -> bool:
        now = time.time()
        if now - self._window_start > 1.0:
            self._counts.clear()
            self._window_start = now
        key = context.get("endpoint", "unknown")
        self._counts[key] += 1
        current_rate = self._counts[key]
        if current_rate <= self.target_rps:
            return True
        return FixedRateSampler(self.target_rps / current_rate).should_sample(context)


DEFAULT_SAMPLER = FixedRateSampler(rate=0.1)


def sample_request(context: Dict, sampler: Optional[SamplingStrategy] = None) -> bool:
    s = sampler or DEFAULT_SAMPLER
    return s.should_sample(context)


# ─────────────────────────────────────────────
# WIDE EVENTS
# ─────────────────────────────────────────────

class WideEvent:
    def __init__(self, name: str):
        self.name = name
        self.trace_id = str(uuid.uuid4())
        self.span_id = str(uuid.uuid4())[:8]
        self.start_time = time.time()
        self.fields: Dict[str, Any] = {}
        self.error: Optional[str] = None

    def add(self, key: str, value: Any) -> "WideEvent":
        self.fields[key] = value
        return self

    def add_many(self, fields: Dict) -> "WideEvent":
        self.fields.update(fields)
        return self

    def set_error(self, error: Exception) -> "WideEvent":
        self.error = str(error)
        self.fields["error"] = True
        self.fields["error_type"] = type(error).__name__
        self.fields["error_message"] = str(error)
        return self

    def to_dict(self) -> Dict:
        duration_ms = (time.time() - self.start_time) * 1000
        return {
            "name": self.name,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round(duration_ms, 3),
            "error": self.error,
            **self.fields,
        }

    def send(self, scrub: bool = True) -> None:
        data = self.to_dict()
        if scrub:
            data = scrub_dict(data)
        record_event(self.name, data)


class TraceContext:
    _current: Dict[str, "TraceContext"] = {}

    def __init__(self, trace_id: Optional[str] = None):
        self.trace_id = trace_id or str(uuid.uuid4())
        self.spans: List[Dict] = []
        self.start_time = time.time()

    def start_span(self, name: str) -> WideEvent:
        event = WideEvent(name)
        event.trace_id = self.trace_id
        return event

    def finish(self) -> None:
        duration_ms = (time.time() - self.start_time) * 1000
        record_event("trace_complete", {
            "trace_id": self.trace_id,
            "duration_ms": round(duration_ms, 3),
            "span_count": len(self.spans),
        })


# ─────────────────────────────────────────────
# EVENT RECORDING
# ─────────────────────────────────────────────

EVENT_HOOKS: List[Callable] = []
EVENT_BUFFER: List[Dict] = []
MAX_BUFFER_SIZE = 1000


def register_event_hook(fn: Callable) -> Callable:
    EVENT_HOOKS.append(fn)
    return fn


def record_event(event_name: str, metadata: Optional[Dict] = None) -> None:
    payload = {
        "event": event_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metadata": scrub_dict(metadata or {}),
    }
    if len(EVENT_BUFFER) < MAX_BUFFER_SIZE:
        EVENT_BUFFER.append(payload)
    for hook in EVENT_HOOKS:
        try:
            hook(payload)
        except Exception as e:
            logger.warning(f"Event hook failed: {e}")
    logger.info(f"[OBSERVE] {event_name}: {json.dumps(payload['metadata'])}")


def flush_events() -> List[Dict]:
    events = list(EVENT_BUFFER)
    EVENT_BUFFER.clear()
    return events


def get_event_count() -> int:
    return len(EVENT_BUFFER)


# ─────────────────────────────────────────────
# REQUEST CONTEXT
# ─────────────────────────────────────────────

def extract_request_context(request: Dict) -> Dict:
    return {
        "request_id": request.get("request_id", str(uuid.uuid4())),
        "user_id": request.get("user", {}).get("id", "anonymous"),
        "user_role": request.get("user", {}).get("role", "unknown"),
        "ip_address": request.get("remote_addr", "unknown"),
        "user_agent": request.get("user_agent", "unknown"),
        "method": request.get("method", "GET"),
        "path": request.get("path", "/"),
        "endpoint": request.get("endpoint", "unknown"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def enrich_context(context: Dict, **kwargs) -> Dict:
    context.update(kwargs)
    return context


# ─────────────────────────────────────────────
# FLASK DECORATORS
# ─────────────────────────────────────────────

def observe(event_name: Optional[str] = None, sample_rate: float = 1.0):
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args, **kwargs):
            name = event_name or fn.__name__
            event = WideEvent(name)
            sampler = FixedRateSampler(sample_rate)
            context = {"endpoint": name}
            should_sample = sampler.should_sample(context)
            try:
                result = fn(*args, **kwargs)
                if should_sample:
                    event.add("success", True)
                    event.send()
                return result
            except Exception as e:
                event.set_error(e)
                event.send()
                raise
        return wrapper
    return decorator


def trace(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        ctx = TraceContext()
        span = ctx.start_span(fn.__name__)
        try:
            result = fn(*args, **kwargs)
            span.add("success", True).send()
            return result
        except Exception as e:
            span.set_error(e).send()
            raise
        finally:
            ctx.finish()
    return wrapper


# ─────────────────────────────────────────────
# SECURITY EVENT LOGGING
# ─────────────────────────────────────────────

SECURITY_EVENT_TYPES = {
    "auth_failure", "auth_success", "privilege_escalation_attempt",
    "rate_limit_exceeded", "invalid_token", "session_expired",
    "password_reset", "account_locked", "suspicious_activity",
    "data_access", "data_modification", "data_deletion",
    "admin_action", "config_change", "permission_denied",
}


def record_security_event(
    event_type: str,
    user_id: Optional[str] = None,
    severity: str = "medium",
    details: Optional[Dict] = None,
) -> None:
    if event_type not in SECURITY_EVENT_TYPES:
        logger.warning(f"Unknown security event type: {event_type}")
    payload = {
        "security_event": True,
        "event_type": event_type,
        "user_id": user_id,
        "severity": severity,
        "details": scrub_dict(details or {}),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    record_event(f"security.{event_type}", payload)
    if severity in ("high", "critical"):
        logger.critical(f"SECURITY ALERT: {event_type} - user={user_id}")


def record_auth_attempt(
    user_id: str,
    success: bool,
    method: str = "password",
    ip_address: Optional[str] = None,
) -> None:
    event_type = "auth_success" if success else "auth_failure"
    record_security_event(
        event_type,
        user_id=user_id,
        severity="low" if success else "medium",
        details={"method": method, "ip_address": ip_address},
    )


def record_access_decision(
    user_id: str,
    resource: str,
    action: str,
    granted: bool,
    reason: Optional[str] = None,
) -> None:
    event_type = "data_access" if granted else "permission_denied"
    record_security_event(
        event_type,
        user_id=user_id,
        severity="low" if granted else "medium",
        details={"resource": resource, "action": action, "reason": reason},
    )


# ─────────────────────────────────────────────
# METRICS
# ─────────────────────────────────────────────

class MetricsCollector:
    def __init__(self):
        self._counters: Dict[str, int] = defaultdict(int)
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._gauges: Dict[str, float] = {}

    def increment(self, name: str, value: int = 1, tags: Optional[Dict] = None) -> None:
        key = self._make_key(name, tags)
        self._counters[key] += value

    def histogram(self, name: str, value: float, tags: Optional[Dict] = None) -> None:
        key = self._make_key(name, tags)
        self._histograms[key].append(value)
        if len(self._histograms[key]) > 10000:
            self._histograms[key] = self._histograms[key][-5000:]

    def gauge(self, name: str, value: float, tags: Optional[Dict] = None) -> None:
        key = self._make_key(name, tags)
        self._gauges[key] = value

    def get_counter(self, name: str, tags: Optional[Dict] = None) -> int:
        return self._counters[self._make_key(name, tags)]

    def get_p99(self, name: str, tags: Optional[Dict] = None) -> Optional[float]:
        values = sorted(self._histograms.get(self._make_key(name, tags), []))
        if not values:
            return None
        idx = int(len(values) * 0.99)
        return values[min(idx, len(values) - 1)]

    def get_average(self, name: str, tags: Optional[Dict] = None) -> Optional[float]:
        values = self._histograms.get(self._make_key(name, tags), [])
        return sum(values) / len(values) if values else None

    def summary(self) -> Dict:
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histograms": {
                k: {
                    "count": len(v),
                    "avg": sum(v) / len(v) if v else 0,
                    "p99": sorted(v)[int(len(v) * 0.99)] if v else 0,
                }
                for k, v in self._histograms.items()
            },
        }

    def reset(self) -> None:
        self._counters.clear()
        self._histograms.clear()
        self._gauges.clear()

    @staticmethod
    def _make_key(name: str, tags: Optional[Dict]) -> str:
        if not tags:
            return name
        tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{name}[{tag_str}]"


METRICS = MetricsCollector()


def record_request_metric(endpoint: str, duration_ms: float, status_code: int) -> None:
    METRICS.increment("requests.total", tags={"endpoint": endpoint})
    METRICS.histogram("requests.duration_ms", duration_ms, tags={"endpoint": endpoint})
    METRICS.increment(
        "requests.by_status",
        tags={"endpoint": endpoint, "status": str(status_code // 100) + "xx"},
    )


# ─────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────

HEALTH_CHECKS: Dict[str, Callable] = {}


def register_health_check(name: str, fn: Callable) -> None:
    HEALTH_CHECKS[name] = fn


def run_health_checks() -> Dict[str, Any]:
    results = {}
    for name, check in HEALTH_CHECKS.items():
        try:
            result = check()
            results[name] = {"status": "ok", "result": result}
        except Exception as e:
            results[name] = {"status": "error", "error": str(e)}
    overall = "ok" if all(r["status"] == "ok" for r in results.values()) else "degraded"
    return {"status": overall, "checks": results, "timestamp": datetime.now(timezone.utc).isoformat()}
