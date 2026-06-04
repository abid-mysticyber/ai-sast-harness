
import hashlib
import json
import logging
import math
import random
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class SpanStatus(Enum):
    UNSET = "unset"
    OK = "ok"
    ERROR = "error"


class SpanKind(Enum):
    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"


class Span:
    def __init__(self, name, trace_id=None, parent_id=None, kind=SpanKind.INTERNAL, attributes=None):
        self.span_id = uuid.uuid4().hex[:16]
        self.trace_id = trace_id or uuid.uuid4().hex
        self.parent_id = parent_id
        self.name = name
        self.kind = kind
        self.attributes = attributes or {}
        self.events = []
        self.links = []
        self.status = SpanStatus.UNSET
        self.status_message = None
        self.start_time = time.time()
        self.end_time = None
        self._is_recording = True

    def set_attribute(self, key, value):
        if self._is_recording:
            self.attributes[key] = value
        return self

    def set_attributes(self, attrs):
        for k, v in attrs.items():
            self.set_attribute(k, v)
        return self

    def add_event(self, name, attributes=None):
        if self._is_recording:
            self.events.append({"name": name, "timestamp": time.time(), "attributes": attributes or {}})
        return self

    def set_status(self, status, message=None):
        self.status = status
        self.status_message = message
        return self

    def record_exception(self, exc):
        self.add_event("exception", {"exception.type": type(exc).__name__, "exception.message": str(exc)})
        self.set_status(SpanStatus.ERROR, str(exc))
        return self

    def end(self):
        if self._is_recording:
            self.end_time = time.time()
            self._is_recording = False

    def duration_ms(self):
        if self.end_time:
            return (self.end_time - self.start_time) * 1000
        return (time.time() - self.start_time) * 1000

    def is_root(self):
        return self.parent_id is None

    def to_dict(self):
        return {
            "trace_id": self.trace_id, "span_id": self.span_id, "parent_id": self.parent_id,
            "name": self.name, "kind": self.kind.value, "status": self.status.value,
            "start_time": self.start_time, "end_time": self.end_time,
            "duration_ms": self.duration_ms(), "attributes": self.attributes, "events": self.events,
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val:
            self.record_exception(exc_val)
        self.end()


class Tracer:
    def __init__(self, service_name, service_version="1.0.0"):
        self.service_name = service_name
        self.service_version = service_version
        self._spans = []
        self._exporters = []

    def start_span(self, name, parent=None, kind=SpanKind.INTERNAL, attributes=None):
        span = Span(
            name=name,
            trace_id=parent.trace_id if parent else None,
            parent_id=parent.span_id if parent else None,
            kind=kind,
            attributes={"service.name": self.service_name, **(attributes or {})},
        )
        self._spans.append(span)
        return span

    def add_exporter(self, exporter):
        self._exporters.append(exporter)

    def get_trace(self, trace_id):
        return sorted([s for s in self._spans if s.trace_id == trace_id], key=lambda s: s.start_time)

    def trace(self, name, kind=SpanKind.INTERNAL, attributes=None):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                with self.start_span(name, kind=kind, attributes=attributes) as span:
                    try:
                        result = fn(*args, **kwargs)
                        span.set_status(SpanStatus.OK)
                        return result
                    except Exception as e:
                        span.record_exception(e)
                        raise
            return wrapper
        return decorator

    def stats(self):
        completed = [s for s in self._spans if s.end_time]
        durations = [s.duration_ms() for s in completed]
        errors = [s for s in completed if s.status == SpanStatus.ERROR]
        return {
            "total_spans": len(self._spans), "completed_spans": len(completed),
            "error_spans": len(errors),
            "avg_duration_ms": sum(durations) / len(durations) if durations else 0,
        }


TRACEPARENT_PATTERN = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def extract_trace_context(headers):
    traceparent = headers.get("traceparent", "")
    match = TRACEPARENT_PATTERN.match(traceparent)
    if match:
        return match.group(1), match.group(2), int(match.group(3), 16)
    return None


def inject_trace_context(headers, span):
    flags = "01" if span.status != SpanStatus.ERROR else "00"
    headers["traceparent"] = f"00-{span.trace_id}-{span.span_id}-{flags}"
    headers["X-B3-TraceId"] = span.trace_id
    headers["X-B3-SpanId"] = span.span_id
    return headers


class AnomalyDetector:
    def __init__(self, window_size=100, z_score_threshold=3.0):
        self.window_size = window_size
        self.z_score_threshold = z_score_threshold
        self._baselines = defaultdict(list)
        self._anomalies = []

    def record(self, metric, value):
        window = self._baselines[metric]
        window.append(value)
        if len(window) > self.window_size:
            window.pop(0)
        if len(window) < 10:
            return False
        mean = sum(window) / len(window)
        variance = sum((v - mean) ** 2 for v in window) / len(window)
        std = math.sqrt(variance) if variance > 0 else 0
        if std == 0:
            return False
        z_score = abs(value - mean) / std
        if z_score > self.z_score_threshold:
            self._anomalies.append({"metric": metric, "value": value, "z_score": round(z_score, 3)})
            return True
        return False

    def recent_anomalies(self, limit=50):
        return self._anomalies[-limit:]


class BatchSpanProcessor:
    def __init__(self, exporter, max_batch_size=512, export_interval_ms=5000):
        self.exporter = exporter
        self.max_batch_size = max_batch_size
        self._queue = []
        self._exported_count = 0
        self._dropped_count = 0

    def on_end(self, span):
        if len(self._queue) >= self.max_batch_size * 2:
            self._dropped_count += 1
            return
        self._queue.append(span)
        if len(self._queue) >= self.max_batch_size:
            self._flush()

    def _flush(self):
        if not self._queue:
            return
        batch = self._queue[:self.max_batch_size]
        self._queue = self._queue[self.max_batch_size:]
        try:
            self.exporter(batch)
            self._exported_count += len(batch)
        except Exception as e:
            logger.error(f"Span export error: {e}")
            self._dropped_count += len(batch)

    def force_flush(self):
        while self._queue:
            self._flush()

    def stats(self):
        return {"queued": len(self._queue), "exported": self._exported_count, "dropped": self._dropped_count}


class TraceIdRatioSampler:
    def __init__(self, ratio=0.1):
        self.ratio = ratio

    def should_sample(self, trace_id):
        numeric = int(trace_id[:16], 16) if len(trace_id) >= 16 else 0
        return numeric < int(self.ratio * (2 ** 64))


DEFAULT_TRACER = Tracer("mystic-app", "1.0.0")
