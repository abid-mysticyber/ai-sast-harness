"""
services.py - Generic CRUD service layer and business logic helpers.
Boring, generic, no security relevance whatsoever.
"""

import json
import logging
import math
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# GENERIC CRUD SERVICE
# ─────────────────────────────────────────────

class CRUDService:
    def __init__(self, store: Optional[Dict] = None):
        self._store: Dict[str, Dict] = store or {}
        self._created_at: Dict[str, float] = {}
        self._updated_at: Dict[str, float] = {}

    def create(self, data: Dict, id_field: str = "id") -> Dict:
        record_id = data.get(id_field) or str(uuid.uuid4())
        record = {id_field: record_id, **data}
        self._store[record_id] = record
        now = time.time()
        self._created_at[record_id] = now
        self._updated_at[record_id] = now
        logger.debug(f"Created record: {record_id}")
        return record

    def get(self, record_id: str) -> Optional[Dict]:
        return self._store.get(record_id)

    def get_many(self, record_ids: List[str]) -> List[Dict]:
        return [self._store[rid] for rid in record_ids if rid in self._store]

    def list_all(self) -> List[Dict]:
        return list(self._store.values())

    def update(self, record_id: str, data: Dict) -> Optional[Dict]:
        if record_id not in self._store:
            return None
        self._store[record_id].update(data)
        self._updated_at[record_id] = time.time()
        return self._store[record_id]

    def delete(self, record_id: str) -> bool:
        if record_id not in self._store:
            return False
        del self._store[record_id]
        self._created_at.pop(record_id, None)
        self._updated_at.pop(record_id, None)
        return True

    def exists(self, record_id: str) -> bool:
        return record_id in self._store

    def count(self) -> int:
        return len(self._store)

    def filter(self, **kwargs) -> List[Dict]:
        return [
            record for record in self._store.values()
            if all(record.get(k) == v for k, v in kwargs.items())
        ]

    def find_first(self, **kwargs) -> Optional[Dict]:
        results = self.filter(**kwargs)
        return results[0] if results else None

    def sort(self, key: str, reverse: bool = False) -> List[Dict]:
        return sorted(self._store.values(), key=lambda r: r.get(key, ""), reverse=reverse)

    def paginate(self, page: int = 1, page_size: int = 20) -> Dict:
        items = self.list_all()
        total = len(items)
        total_pages = max(1, math.ceil(total / page_size))
        page = max(1, min(page, total_pages))
        start = (page - 1) * page_size
        return {
            "items": items[start:start + page_size],
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
        }

    def bulk_create(self, records: List[Dict]) -> List[Dict]:
        return [self.create(r) for r in records]

    def bulk_delete(self, record_ids: List[str]) -> int:
        return sum(1 for rid in record_ids if self.delete(rid))

    def clear(self) -> None:
        self._store.clear()
        self._created_at.clear()
        self._updated_at.clear()

    def get_created_at(self, record_id: str) -> Optional[float]:
        return self._created_at.get(record_id)

    def get_updated_at(self, record_id: str) -> Optional[float]:
        return self._updated_at.get(record_id)


# ─────────────────────────────────────────────
# EMAIL TEMPLATE SERVICE
# ─────────────────────────────────────────────

class EmailTemplate:
    def __init__(self, name: str, subject: str, body: str):
        self.name = name
        self.subject = subject
        self.body = body

    def render(self, context: Dict) -> Tuple[str, str]:
        subject = self.subject
        body = self.body
        for key, value in context.items():
            placeholder = f"{{{{{key}}}}}"
            subject = subject.replace(placeholder, str(value))
            body = body.replace(placeholder, str(value))
        return subject, body

    def to_dict(self) -> Dict:
        return {"name": self.name, "subject": self.subject, "body": self.body}


EMAIL_TEMPLATES: Dict[str, EmailTemplate] = {}


def register_template(name: str, subject: str, body: str) -> EmailTemplate:
    template = EmailTemplate(name, subject, body)
    EMAIL_TEMPLATES[name] = template
    return template


def render_template(name: str, context: Dict) -> Tuple[str, str]:
    template = EMAIL_TEMPLATES.get(name)
    if not template:
        raise ValueError(f"Template not found: {name}")
    return template.render(context)


def list_templates() -> List[str]:
    return list(EMAIL_TEMPLATES.keys())


register_template(
    "welcome",
    "Welcome to {{app_name}}, {{first_name}}!",
    "Hi {{first_name}},\n\nWelcome to {{app_name}}. Your account has been created.\n\nBest regards,\nThe {{app_name}} Team",
)

register_template(
    "password_reset",
    "Reset your {{app_name}} password",
    "Hi {{first_name}},\n\nClick the link below to reset your password:\n{{reset_link}}\n\nThis link expires in {{expiry_hours}} hours.\n\nBest regards,\nThe {{app_name}} Team",
)

register_template(
    "notification",
    "{{subject}}",
    "Hi {{first_name}},\n\n{{message}}\n\nBest regards,\nThe {{app_name}} Team",
)

register_template(
    "report_ready",
    "Your {{report_name}} report is ready",
    "Hi {{first_name}},\n\nYour report '{{report_name}}' generated on {{date}} is now available.\n\nTotal records: {{record_count}}\n\nBest regards,\nThe {{app_name}} Team",
)


# ─────────────────────────────────────────────
# CACHE SERVICE
# ─────────────────────────────────────────────

class SimpleCache:
    def __init__(self, default_ttl: int = 300):
        self._store: Dict[str, Tuple[Any, float]] = {}
        self.default_ttl = default_ttl
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        if not entry:
            self.misses += 1
            return None
        value, expires_at = entry
        if time.time() > expires_at:
            del self._store[key]
            self.misses += 1
            return None
        self.hits += 1
        return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        expires_at = time.time() + (ttl or self.default_ttl)
        self._store[key] = (value, expires_at)

    def delete(self, key: str) -> bool:
        return self._store.pop(key, None) is not None

    def clear(self) -> None:
        self._store.clear()

    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def size(self) -> int:
        return len(self._store)

    def evict_expired(self) -> int:
        now = time.time()
        expired = [k for k, (_, exp) in self._store.items() if exp < now]
        for k in expired:
            del self._store[k]
        return len(expired)

    def keys(self) -> List[str]:
        return list(self._store.keys())

    def stats(self) -> Dict:
        return {
            "size": self.size(),
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": self.hit_rate(),
        }


# ─────────────────────────────────────────────
# NOTIFICATION SERVICE
# ─────────────────────────────────────────────

class Notification:
    def __init__(self, title: str, message: str, recipient: str, channel: str = "email"):
        self.id = str(uuid.uuid4())
        self.title = title
        self.message = message
        self.recipient = recipient
        self.channel = channel
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.sent = False
        self.sent_at: Optional[str] = None
        self.error: Optional[str] = None

    def mark_sent(self) -> None:
        self.sent = True
        self.sent_at = datetime.now(timezone.utc).isoformat()

    def mark_failed(self, error: str) -> None:
        self.error = error

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "recipient": self.recipient,
            "channel": self.channel,
            "created_at": self.created_at,
            "sent": self.sent,
            "sent_at": self.sent_at,
            "error": self.error,
        }


class NotificationQueue:
    def __init__(self):
        self._queue: List[Notification] = []
        self._sent: List[Notification] = []
        self._failed: List[Notification] = []

    def enqueue(self, notification: Notification) -> None:
        self._queue.append(notification)

    def process(self, sender: Callable[[Notification], bool]) -> Dict:
        processed = 0
        succeeded = 0
        failed = 0
        while self._queue:
            notification = self._queue.pop(0)
            try:
                success = sender(notification)
                if success:
                    notification.mark_sent()
                    self._sent.append(notification)
                    succeeded += 1
                else:
                    notification.mark_failed("Sender returned False")
                    self._failed.append(notification)
                    failed += 1
            except Exception as e:
                notification.mark_failed(str(e))
                self._failed.append(notification)
                failed += 1
            processed += 1
        return {"processed": processed, "succeeded": succeeded, "failed": failed}

    def pending_count(self) -> int:
        return len(self._queue)

    def sent_count(self) -> int:
        return len(self._sent)

    def failed_count(self) -> int:
        return len(self._failed)

    def get_failed(self) -> List[Dict]:
        return [n.to_dict() for n in self._failed]

    def retry_failed(self, sender: Callable[[Notification], bool]) -> int:
        failed = list(self._failed)
        self._failed.clear()
        self._queue.extend(failed)
        result = self.process(sender)
        return result["succeeded"]


# ─────────────────────────────────────────────
# REPORT SERVICE
# ─────────────────────────────────────────────

class Report:
    def __init__(self, name: str, data: List[Dict]):
        self.id = str(uuid.uuid4())
        self.name = name
        self.data = data
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.metadata: Dict = {}

    def add_metadata(self, key: str, value: Any) -> None:
        self.metadata[key] = value

    def filter(self, **kwargs) -> "Report":
        filtered = [
            row for row in self.data
            if all(row.get(k) == v for k, v in kwargs.items())
        ]
        return Report(f"{self.name}_filtered", filtered)

    def sort(self, key: str, reverse: bool = False) -> "Report":
        sorted_data = sorted(self.data, key=lambda r: r.get(key, ""), reverse=reverse)
        return Report(f"{self.name}_sorted", sorted_data)

    def aggregate(self, group_key: str, value_key: str, agg: str = "sum") -> Dict:
        groups: Dict[str, List[float]] = defaultdict(list)
        for row in self.data:
            try:
                groups[row.get(group_key, "unknown")].append(float(row.get(value_key, 0)))
            except (ValueError, TypeError):
                pass
        result = {}
        for group, values in groups.items():
            if agg == "sum":
                result[group] = sum(values)
            elif agg == "avg":
                result[group] = sum(values) / len(values) if values else 0
            elif agg == "count":
                result[group] = len(values)
            elif agg == "max":
                result[group] = max(values) if values else 0
            elif agg == "min":
                result[group] = min(values) if values else 0
        return result

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "record_count": len(self.data),
            "created_at": self.created_at,
            "metadata": self.metadata,
        }

    def summary(self) -> Dict:
        return {
            **self.to_dict(),
            "columns": list(self.data[0].keys()) if self.data else [],
            "sample": self.data[:3],
        }
