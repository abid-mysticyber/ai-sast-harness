"""
notifications.py - Email, SMS, and push notification queue management.
Generic notification utilities with no security relevance.
"""

import json
import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# ENUMS AND CONSTANTS
# ─────────────────────────────────────────────

class Channel(Enum):
    EMAIL = "email"
    SMS = "sms"
    PUSH = "push"
    WEBHOOK = "webhook"
    SLACK = "slack"
    TEAMS = "teams"


class Priority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    URGENT = 4


class Status(Enum):
    PENDING = "pending"
    QUEUED = "queued"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"
    BOUNCED = "bounced"


MAX_RETRIES = 3
RETRY_DELAYS = [60, 300, 900]
BATCH_SIZE = 100


# ─────────────────────────────────────────────
# NOTIFICATION MODEL
# ─────────────────────────────────────────────

class Notification:
    def __init__(
        self,
        recipient: str,
        channel: Channel,
        subject: str,
        body: str,
        priority: Priority = Priority.NORMAL,
        metadata: Optional[Dict] = None,
        scheduled_at: Optional[float] = None,
    ):
        self.id = str(uuid.uuid4())
        self.recipient = recipient
        self.channel = channel
        self.subject = subject
        self.body = body
        self.priority = priority
        self.metadata = metadata or {}
        self.scheduled_at = scheduled_at
        self.status = Status.PENDING
        self.attempts = 0
        self.last_attempt: Optional[float] = None
        self.sent_at: Optional[float] = None
        self.error: Optional[str] = None
        self.created_at = time.time()

    def can_retry(self) -> bool:
        return self.attempts < MAX_RETRIES and self.status in (Status.FAILED, Status.RETRYING)

    def next_retry_delay(self) -> int:
        idx = min(self.attempts, len(RETRY_DELAYS) - 1)
        return RETRY_DELAYS[idx]

    def mark_sent(self) -> None:
        self.status = Status.SENT
        self.sent_at = time.time()

    def mark_failed(self, error: str) -> None:
        self.error = error
        self.attempts += 1
        self.last_attempt = time.time()
        if self.can_retry():
            self.status = Status.RETRYING
        else:
            self.status = Status.FAILED

    def mark_cancelled(self) -> None:
        self.status = Status.CANCELLED

    def is_ready(self) -> bool:
        if self.scheduled_at and time.time() < self.scheduled_at:
            return False
        if self.status == Status.RETRYING and self.last_attempt:
            delay = self.next_retry_delay()
            if time.time() - self.last_attempt < delay:
                return False
        return self.status in (Status.PENDING, Status.QUEUED, Status.RETRYING)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "recipient": self.recipient,
            "channel": self.channel.value,
            "subject": self.subject,
            "priority": self.priority.value,
            "status": self.status.value,
            "attempts": self.attempts,
            "created_at": self.created_at,
            "sent_at": self.sent_at,
            "error": self.error,
        }


# ─────────────────────────────────────────────
# TEMPLATE ENGINE
# ─────────────────────────────────────────────

class TemplateEngine:
    def __init__(self):
        self._templates: Dict[str, Dict[str, str]] = {}
        self._partials: Dict[str, str] = {}

    def register(self, name: str, subject: str, body: str, channel: Channel = Channel.EMAIL) -> None:
        key = f"{channel.value}:{name}"
        self._templates[key] = {"subject": subject, "body": body, "channel": channel.value}

    def register_partial(self, name: str, content: str) -> None:
        self._partials[name] = content

    def render(self, name: str, context: Dict, channel: Channel = Channel.EMAIL) -> Tuple[str, str]:
        key = f"{channel.value}:{name}"
        template = self._templates.get(key)
        if not template:
            raise ValueError(f"Template not found: {key}")
        subject = self._render_string(template["subject"], context)
        body = self._render_string(template["body"], context)
        return subject, body

    def _render_string(self, template: str, context: Dict) -> str:
        for key, value in context.items():
            template = template.replace(f"{{{{{key}}}}}", str(value))
        for partial_name, partial_content in self._partials.items():
            rendered_partial = self._render_string(partial_content, context)
            template = template.replace(f"{{{{>{partial_name}}}}}", rendered_partial)
        return template

    def list_templates(self) -> List[str]:
        return list(self._templates.keys())

    def has_template(self, name: str, channel: Channel = Channel.EMAIL) -> bool:
        return f"{channel.value}:{name}" in self._templates


DEFAULT_ENGINE = TemplateEngine()
DEFAULT_ENGINE.register_partial("footer", "\n\n--\nSent by {{app_name}} | Unsubscribe: {{unsubscribe_url}}")
DEFAULT_ENGINE.register("welcome", "Welcome to {{app_name}}", "Hi {{first_name}},\n\nWelcome aboard!{{>footer}}")
DEFAULT_ENGINE.register("password_reset", "Reset your password", "Hi {{first_name}},\n\nReset link: {{reset_link}}\n\nExpires in {{expiry_hours}} hours.{{>footer}}")
DEFAULT_ENGINE.register("digest", "Your {{period}} digest", "Hi {{first_name}},\n\nHere is your summary:\n\n{{summary}}{{>footer}}")
DEFAULT_ENGINE.register("alert", "Alert: {{alert_type}}", "Hi {{first_name}},\n\n{{message}}{{>footer}}")
DEFAULT_ENGINE.register("invoice", "Invoice #{{invoice_number}}", "Hi {{first_name}},\n\nYour invoice for {{amount}} is ready.{{>footer}}")


# ─────────────────────────────────────────────
# NOTIFICATION QUEUE
# ─────────────────────────────────────────────

class NotificationQueue:
    def __init__(self, name: str = "default"):
        self.name = name
        self._queues: Dict[int, List[Notification]] = {p.value: [] for p in Priority}
        self._processing: Dict[str, Notification] = {}
        self._sent: List[Notification] = []
        self._failed: List[Notification] = []
        self._stats: Dict[str, int] = defaultdict(int)

    def enqueue(self, notification: Notification) -> str:
        self._queues[notification.priority.value].append(notification)
        notification.status = Status.QUEUED
        self._stats["enqueued"] += 1
        logger.debug(f"Queued notification {notification.id} via {notification.channel.value}")
        return notification.id

    def dequeue(self, batch_size: int = BATCH_SIZE) -> List[Notification]:
        ready = []
        for priority in sorted(self._queues.keys(), reverse=True):
            for notification in list(self._queues[priority]):
                if notification.is_ready():
                    self._queues[priority].remove(notification)
                    self._processing[notification.id] = notification
                    ready.append(notification)
                    if len(ready) >= batch_size:
                        return ready
        return ready

    def complete(self, notification_id: str, success: bool, error: Optional[str] = None) -> None:
        notification = self._processing.pop(notification_id, None)
        if not notification:
            return
        if success:
            notification.mark_sent()
            self._sent.append(notification)
            self._stats["sent"] += 1
        else:
            notification.mark_failed(error or "Unknown error")
            if notification.status == Status.RETRYING:
                self._queues[notification.priority.value].append(notification)
                self._stats["retried"] += 1
            else:
                self._failed.append(notification)
                self._stats["failed"] += 1

    def cancel(self, notification_id: str) -> bool:
        for priority_queue in self._queues.values():
            for n in priority_queue:
                if n.id == notification_id:
                    priority_queue.remove(n)
                    n.mark_cancelled()
                    self._stats["cancelled"] += 1
                    return True
        return False

    def pending_count(self) -> int:
        return sum(len(q) for q in self._queues.values())

    def stats(self) -> Dict:
        return {
            "name": self.name,
            "pending": self.pending_count(),
            "processing": len(self._processing),
            **dict(self._stats),
        }

    def drain(self, sender: Callable[[Notification], bool]) -> Dict[str, int]:
        processed = 0
        succeeded = 0
        failed = 0
        batch = self.dequeue()
        while batch:
            for notification in batch:
                try:
                    result = sender(notification)
                    self.complete(notification.id, result)
                    if result:
                        succeeded += 1
                    else:
                        failed += 1
                except Exception as e:
                    self.complete(notification.id, False, str(e))
                    failed += 1
                processed += 1
            batch = self.dequeue()
        return {"processed": processed, "succeeded": succeeded, "failed": failed}


# ─────────────────────────────────────────────
# RATE LIMITER
# ─────────────────────────────────────────────

class NotificationRateLimiter:
    def __init__(self):
        self._windows: Dict[str, List[float]] = defaultdict(list)
        self._limits: Dict[str, Tuple[int, int]] = {}

    def set_limit(self, key: str, max_count: int, window_seconds: int) -> None:
        self._limits[key] = (max_count, window_seconds)

    def is_allowed(self, key: str) -> bool:
        if key not in self._limits:
            return True
        max_count, window_seconds = self._limits[key]
        now = time.time()
        self._windows[key] = [t for t in self._windows[key] if now - t < window_seconds]
        if len(self._windows[key]) >= max_count:
            return False
        self._windows[key].append(now)
        return True

    def remaining(self, key: str) -> int:
        if key not in self._limits:
            return 999
        max_count, window_seconds = self._limits[key]
        now = time.time()
        recent = [t for t in self._windows.get(key, []) if now - t < window_seconds]
        return max(0, max_count - len(recent))


# ─────────────────────────────────────────────
# DIGEST BUILDER
# ─────────────────────────────────────────────

class DigestBuilder:
    def __init__(self, title: str):
        self.title = title
        self._items: List[Dict] = []
        self._sections: Dict[str, List[Dict]] = defaultdict(list)

    def add_item(self, title: str, body: str, url: Optional[str] = None, section: str = "default") -> None:
        item = {"title": title, "body": body, "url": url}
        self._items.append(item)
        self._sections[section].append(item)

    def add_section(self, name: str, items: List[Dict]) -> None:
        self._sections[name].extend(items)
        self._items.extend(items)

    def build_text(self) -> str:
        lines = [self.title, "=" * len(self.title), ""]
        for section, items in self._sections.items():
            if section != "default":
                lines.append(f"## {section}")
                lines.append("")
            for item in items:
                lines.append(f"• {item['title']}")
                if item.get("body"):
                    lines.append(f"  {item['body']}")
                if item.get("url"):
                    lines.append(f"  {item['url']}")
                lines.append("")
        return "\n".join(lines)

    def item_count(self) -> int:
        return len(self._items)

    def section_count(self) -> int:
        return len(self._sections)
