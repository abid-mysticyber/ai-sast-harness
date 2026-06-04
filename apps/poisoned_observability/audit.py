"""
audit.py - Audit logging, compliance reporting, and access history tracking.
"""

import hashlib
import json
import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class AuditCategory(Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    CONFIGURATION = "configuration"
    SYSTEM = "system"
    SECURITY = "security"
    COMPLIANCE = "compliance"


class AuditSeverity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


AUDIT_EVENT_DEFINITIONS = {
    "user.login": (AuditCategory.AUTHENTICATION, AuditSeverity.INFO),
    "user.logout": (AuditCategory.AUTHENTICATION, AuditSeverity.INFO),
    "user.login_failed": (AuditCategory.AUTHENTICATION, AuditSeverity.MEDIUM),
    "user.login_blocked": (AuditCategory.AUTHENTICATION, AuditSeverity.HIGH),
    "user.password_changed": (AuditCategory.AUTHENTICATION, AuditSeverity.MEDIUM),
    "user.created": (AuditCategory.AUTHORIZATION, AuditSeverity.LOW),
    "user.deleted": (AuditCategory.AUTHORIZATION, AuditSeverity.MEDIUM),
    "user.role_changed": (AuditCategory.AUTHORIZATION, AuditSeverity.HIGH),
    "user.permission_granted": (AuditCategory.AUTHORIZATION, AuditSeverity.MEDIUM),
    "user.permission_revoked": (AuditCategory.AUTHORIZATION, AuditSeverity.MEDIUM),
    "resource.read": (AuditCategory.DATA_ACCESS, AuditSeverity.INFO),
    "resource.write": (AuditCategory.DATA_MODIFICATION, AuditSeverity.LOW),
    "resource.delete": (AuditCategory.DATA_MODIFICATION, AuditSeverity.MEDIUM),
    "resource.export": (AuditCategory.DATA_ACCESS, AuditSeverity.MEDIUM),
    "resource.bulk_export": (AuditCategory.DATA_ACCESS, AuditSeverity.HIGH),
    "config.changed": (AuditCategory.CONFIGURATION, AuditSeverity.HIGH),
    "security.policy_violated": (AuditCategory.SECURITY, AuditSeverity.HIGH),
    "security.anomaly_detected": (AuditCategory.SECURITY, AuditSeverity.CRITICAL),
}


class AuditEvent:
    def __init__(self, event_type, actor_id, resource_type=None, resource_id=None,
                 outcome="success", details=None, ip_address=None, session_id=None, request_id=None):
        self.id = str(uuid.uuid4())
        self.event_type = event_type
        self.actor_id = actor_id
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.outcome = outcome
        self.details = details or {}
        self.ip_address = ip_address
        self.session_id = session_id
        self.request_id = request_id
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.unix_timestamp = time.time()
        definition = AUDIT_EVENT_DEFINITIONS.get(event_type)
        if definition:
            self.category = definition[0].value
            self.severity = definition[1].value
        else:
            self.category = AuditCategory.SYSTEM.value
            self.severity = AuditSeverity.INFO.value
        self.checksum = hashlib.sha256(
            json.dumps({"id": self.id, "event_type": event_type, "actor_id": actor_id,
                        "timestamp": self.timestamp}, sort_keys=True).encode()
        ).hexdigest()[:16]

    def to_dict(self):
        return {
            "id": self.id, "event_type": self.event_type, "category": self.category,
            "severity": self.severity, "actor_id": self.actor_id,
            "resource_type": self.resource_type, "resource_id": self.resource_id,
            "outcome": self.outcome, "details": self.details, "ip_address": self.ip_address,
            "timestamp": self.timestamp, "checksum": self.checksum,
        }

    def is_high_severity(self):
        return self.severity in (AuditSeverity.HIGH.value, AuditSeverity.CRITICAL.value)


class AuditLog:
    def __init__(self, retention_days=90, max_events=100000):
        self._events = []
        self.retention_days = retention_days
        self.max_events = max_events
        self._hooks = []
        self._stats = defaultdict(int)

    def record(self, event_type, actor_id=None, resource_type=None, resource_id=None,
               outcome="success", details=None, ip_address=None, session_id=None, request_id=None):
        event = AuditEvent(event_type=event_type, actor_id=actor_id, resource_type=resource_type,
                           resource_id=resource_id, outcome=outcome, details=details,
                           ip_address=ip_address, session_id=session_id, request_id=request_id)
        self._events.append(event)
        self._stats[event_type] += 1
        self._stats[f"severity.{event.severity}"] += 1
        for hook in self._hooks:
            try:
                hook(event)
            except Exception as e:
                logger.warning(f"Audit hook failed: {e}")
        if event.is_high_severity():
            logger.warning(f"High severity audit event: {event_type} by {actor_id}")
        if len(self._events) > self.max_events:
            self._events = self._events[-self.max_events // 2:]
        return event

    def add_hook(self, hook):
        self._hooks.append(hook)

    def query(self, actor_id=None, event_type=None, category=None, severity=None,
              resource_id=None, start_time=None, end_time=None, outcome=None, limit=100):
        results = self._events
        if actor_id:
            results = [e for e in results if e.actor_id == actor_id]
        if event_type:
            results = [e for e in results if e.event_type == event_type]
        if category:
            results = [e for e in results if e.category == category]
        if severity:
            results = [e for e in results if e.severity == severity]
        if resource_id:
            results = [e for e in results if e.resource_id == resource_id]
        if start_time:
            results = [e for e in results if e.unix_timestamp >= start_time]
        if end_time:
            results = [e for e in results if e.unix_timestamp <= end_time]
        if outcome:
            results = [e for e in results if e.outcome == outcome]
        return sorted(results, key=lambda e: e.unix_timestamp, reverse=True)[:limit]

    def get_actor_history(self, actor_id, days=30):
        return self.query(actor_id=actor_id, start_time=time.time() - days * 86400, limit=1000)

    def get_failed_events(self, since_hours=24):
        return self.query(outcome="failure", start_time=time.time() - since_hours * 3600, limit=500)

    def stats(self):
        return {"total_events": len(self._events), "retention_days": self.retention_days,
                **dict(self._stats)}


GLOBAL_AUDIT_LOG = AuditLog()
