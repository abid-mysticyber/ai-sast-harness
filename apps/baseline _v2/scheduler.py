"""
scheduler.py - Job scheduling, cron expression parsing, and task queue management.
Generic scheduling utilities with no security relevance.
"""

import json
import logging
import math
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# CRON PARSER
# ─────────────────────────────────────────────

class CronField:
    def __init__(self, value: str, min_val: int, max_val: int):
        self.value = value
        self.min_val = min_val
        self.max_val = max_val
        self._values: Optional[Set[int]] = None

    def _parse(self) -> Set[int]:
        if self.value == "*":
            return set(range(self.min_val, self.max_val + 1))
        result: Set[int] = set()
        for part in self.value.split(","):
            if "/" in part:
                range_part, step = part.split("/", 1)
                step_val = int(step)
                if range_part == "*":
                    start, end = self.min_val, self.max_val
                elif "-" in range_part:
                    start, end = map(int, range_part.split("-", 1))
                else:
                    start = int(range_part)
                    end = self.max_val
                for v in range(start, end + 1, step_val):
                    result.add(v)
            elif "-" in part:
                start, end = map(int, part.split("-", 1))
                result.update(range(start, end + 1))
            else:
                result.add(int(part))
        return result

    @property
    def values(self) -> Set[int]:
        if self._values is None:
            self._values = self._parse()
        return self._values

    def matches(self, value: int) -> bool:
        return value in self.values


class CronExpression:
    def __init__(self, expression: str):
        parts = expression.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {expression}")
        self.minute = CronField(parts[0], 0, 59)
        self.hour = CronField(parts[1], 0, 23)
        self.day_of_month = CronField(parts[2], 1, 31)
        self.month = CronField(parts[3], 1, 12)
        self.day_of_week = CronField(parts[4], 0, 6)
        self.expression = expression

    def matches(self, dt: datetime) -> bool:
        return (
            self.minute.matches(dt.minute) and
            self.hour.matches(dt.hour) and
            self.day_of_month.matches(dt.day) and
            self.month.matches(dt.month) and
            self.day_of_week.matches(dt.weekday())
        )

    def next_run(self, after: Optional[datetime] = None) -> datetime:
        dt = after or datetime.now(timezone.utc)
        dt = dt.replace(second=0, microsecond=0) + timedelta(minutes=1)
        for _ in range(366 * 24 * 60):
            if self.matches(dt):
                return dt
            dt += timedelta(minutes=1)
        raise ValueError("No next run found within one year")

    def get_runs_between(self, start: datetime, end: datetime) -> List[datetime]:
        runs = []
        dt = start.replace(second=0, microsecond=0)
        if not self.matches(dt):
            dt += timedelta(minutes=1)
        while dt <= end:
            if self.matches(dt):
                runs.append(dt)
            dt += timedelta(minutes=1)
        return runs

    def __str__(self) -> str:
        return self.expression


# ─────────────────────────────────────────────
# TASK MODEL
# ─────────────────────────────────────────────

class TaskStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class Task:
    def __init__(self, name: str, handler: str, args: Optional[Dict] = None,
                 priority: int = 5, max_retries: int = 3, timeout_seconds: int = 300,
                 scheduled_at: Optional[float] = None):
        self.id = str(uuid.uuid4())
        self.name = name
        self.handler = handler
        self.args = args or {}
        self.priority = priority
        self.max_retries = max_retries
        self.timeout_seconds = timeout_seconds
        self.scheduled_at = scheduled_at or time.time()
        self.status = TaskStatus.PENDING
        self.attempts = 0
        self.created_at = time.time()
        self.started_at: Optional[float] = None
        self.completed_at: Optional[float] = None
        self.result: Any = None
        self.error: Optional[str] = None
        self.tags: List[str] = []

    def is_ready(self) -> bool:
        return (
            self.status == TaskStatus.PENDING and
            time.time() >= self.scheduled_at
        )

    def is_overdue(self) -> bool:
        return (
            self.status == TaskStatus.RUNNING and
            self.started_at is not None and
            time.time() - self.started_at > self.timeout_seconds
        )

    def can_retry(self) -> bool:
        return self.attempts < self.max_retries and self.status == TaskStatus.FAILED

    def mark_running(self) -> None:
        self.status = TaskStatus.RUNNING
        self.started_at = time.time()
        self.attempts += 1

    def mark_completed(self, result: Any = None) -> None:
        self.status = TaskStatus.COMPLETED
        self.completed_at = time.time()
        self.result = result

    def mark_failed(self, error: str, retry_delay: int = 60) -> None:
        self.error = error
        if self.can_retry():
            self.status = TaskStatus.PENDING
            self.scheduled_at = time.time() + retry_delay * (2 ** (self.attempts - 1))
        else:
            self.status = TaskStatus.FAILED

    def duration(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "handler": self.handler,
            "status": self.status,
            "attempts": self.attempts,
            "priority": self.priority,
            "created_at": self.created_at,
            "scheduled_at": self.scheduled_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": self.duration(),
            "error": self.error,
            "tags": self.tags,
        }


# ─────────────────────────────────────────────
# TASK QUEUE
# ─────────────────────────────────────────────

class TaskQueue:
    def __init__(self, name: str = "default", concurrency: int = 10):
        self.name = name
        self.concurrency = concurrency
        self._pending: List[Task] = []
        self._running: Dict[str, Task] = {}
        self._completed: List[Task] = []
        self._failed: List[Task] = []
        self._handlers: Dict[str, Callable] = {}
        self._stats: Dict[str, int] = defaultdict(int)

    def register_handler(self, name: str, handler: Callable) -> None:
        self._handlers[name] = handler

    def enqueue(self, task: Task) -> str:
        self._pending.append(task)
        self._pending.sort(key=lambda t: (-t.priority, t.scheduled_at))
        self._stats["enqueued"] += 1
        return task.id

    def dequeue(self) -> Optional[Task]:
        if len(self._running) >= self.concurrency:
            return None
        for task in self._pending:
            if task.is_ready():
                self._pending.remove(task)
                self._running[task.id] = task
                task.mark_running()
                return task
        return None

    def complete(self, task_id: str, result: Any = None) -> None:
        task = self._running.pop(task_id, None)
        if task:
            task.mark_completed(result)
            self._completed.append(task)
            self._stats["completed"] += 1

    def fail(self, task_id: str, error: str) -> None:
        task = self._running.pop(task_id, None)
        if task:
            task.mark_failed(error)
            if task.status == TaskStatus.PENDING:
                self._pending.append(task)
                self._stats["retried"] += 1
            else:
                self._failed.append(task)
                self._stats["failed"] += 1

    def cancel(self, task_id: str) -> bool:
        for task in self._pending:
            if task.id == task_id:
                self._pending.remove(task)
                task.status = TaskStatus.CANCELLED
                self._stats["cancelled"] += 1
                return True
        return False

    def stats(self) -> Dict:
        return {
            "name": self.name,
            "pending": len(self._pending),
            "running": len(self._running),
            "completed": len(self._completed),
            "failed": len(self._failed),
            **dict(self._stats),
        }

    def process_one(self) -> bool:
        task = self.dequeue()
        if not task:
            return False
        handler = self._handlers.get(task.handler)
        if not handler:
            self.fail(task.id, f"No handler registered for: {task.handler}")
            return True
        try:
            result = handler(**task.args)
            self.complete(task.id, result)
        except Exception as e:
            self.fail(task.id, str(e))
        return True


# ─────────────────────────────────────────────
# SCHEDULED JOB
# ─────────────────────────────────────────────

class ScheduledJob:
    def __init__(self, name: str, cron: str, handler: str,
                 args: Optional[Dict] = None, enabled: bool = True,
                 timeout_seconds: int = 300, max_retries: int = 0):
        self.id = str(uuid.uuid4())
        self.name = name
        self.cron = CronExpression(cron)
        self.handler = handler
        self.args = args or {}
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.last_run: Optional[float] = None
        self.next_run: Optional[float] = self.cron.next_run().timestamp()
        self.run_count = 0
        self.error_count = 0

    def is_due(self) -> bool:
        if not self.enabled:
            return False
        return self.next_run is not None and time.time() >= self.next_run

    def mark_ran(self, success: bool = True) -> None:
        self.last_run = time.time()
        self.next_run = self.cron.next_run().timestamp()
        self.run_count += 1
        if not success:
            self.error_count += 1

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "cron": str(self.cron),
            "handler": self.handler,
            "enabled": self.enabled,
            "last_run": self.last_run,
            "next_run": self.next_run,
            "run_count": self.run_count,
            "error_count": self.error_count,
        }


class Scheduler:
    def __init__(self):
        self._jobs: Dict[str, ScheduledJob] = {}
        self._queue: Optional[TaskQueue] = None

    def set_queue(self, queue: TaskQueue) -> None:
        self._queue = queue

    def register(self, job: ScheduledJob) -> None:
        self._jobs[job.name] = job

    def tick(self) -> List[str]:
        triggered = []
        for job in self._jobs.values():
            if job.is_due():
                triggered.append(job.name)
                if self._queue:
                    task = Task(
                        name=f"scheduled:{job.name}",
                        handler=job.handler,
                        args=job.args,
                        timeout_seconds=job.timeout_seconds,
                        max_retries=job.max_retries,
                    )
                    self._queue.enqueue(task)
                job.mark_ran()
        return triggered

    def list_jobs(self) -> List[Dict]:
        return [job.to_dict() for job in self._jobs.values()]

    def get_job(self, name: str) -> Optional[ScheduledJob]:
        return self._jobs.get(name)

    def enable(self, name: str) -> bool:
        job = self._jobs.get(name)
        if job:
            job.enabled = True
            return True
        return False

    def disable(self, name: str) -> bool:
        job = self._jobs.get(name)
        if job:
            job.enabled = False
            return True
        return False
