"""
analytics.py - Data aggregation, reporting, and statistical helpers.
Generic business analytics utilities with no security relevance.
"""

import csv
import io
import json
import math
import os
import time
import uuid
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# ─────────────────────────────────────────────
# TIME SERIES
# ─────────────────────────────────────────────

def bucket_by_hour(events: List[Dict], timestamp_field: str = "timestamp") -> Dict[str, List[Dict]]:
    buckets: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        ts = event.get(timestamp_field, "")
        if isinstance(ts, str) and len(ts) >= 13:
            hour_key = ts[:13]
        elif isinstance(ts, (int, float)):
            hour_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H")
        else:
            hour_key = "unknown"
        buckets[hour_key].append(event)
    return dict(buckets)


def bucket_by_day(events: List[Dict], timestamp_field: str = "timestamp") -> Dict[str, List[Dict]]:
    buckets: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        ts = event.get(timestamp_field, "")
        if isinstance(ts, str) and len(ts) >= 10:
            day_key = ts[:10]
        elif isinstance(ts, (int, float)):
            day_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
        else:
            day_key = "unknown"
        buckets[day_key].append(event)
    return dict(buckets)


def bucket_by_week(events: List[Dict], timestamp_field: str = "timestamp") -> Dict[str, List[Dict]]:
    buckets: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        ts = event.get(timestamp_field, "")
        try:
            if isinstance(ts, str):
                dt = datetime.fromisoformat(ts[:19])
            else:
                dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
            iso_week = dt.strftime("%Y-W%V")
        except Exception:
            iso_week = "unknown"
        buckets[iso_week].append(event)
    return dict(buckets)


def resample_time_series(data: Dict[str, float], interval: str = "day") -> Dict[str, float]:
    if not data:
        return {}
    sorted_keys = sorted(data.keys())
    if interval == "day":
        result: Dict[str, float] = defaultdict(float)
        for k, v in data.items():
            day_key = k[:10]
            result[day_key] += v
        return dict(result)
    return data


def rolling_sum(values: List[float], window: int) -> List[float]:
    result = []
    for i in range(len(values)):
        start = max(0, i - window + 1)
        result.append(sum(values[start:i + 1]))
    return result


def rolling_max(values: List[float], window: int) -> List[float]:
    result = []
    for i in range(len(values)):
        start = max(0, i - window + 1)
        result.append(max(values[start:i + 1]))
    return result


def rolling_min(values: List[float], window: int) -> List[float]:
    result = []
    for i in range(len(values)):
        start = max(0, i - window + 1)
        result.append(min(values[start:i + 1]))
    return result


def fill_missing_dates(data: Dict[str, float], start: date, end: date, fill_value: float = 0.0) -> Dict[str, float]:
    result = {}
    current = start
    while current <= end:
        key = current.strftime("%Y-%m-%d")
        result[key] = data.get(key, fill_value)
        current += timedelta(days=1)
    return result


def detect_trend(values: List[float]) -> str:
    if len(values) < 2:
        return "insufficient_data"
    first_half = values[:len(values) // 2]
    second_half = values[len(values) // 2:]
    avg_first = sum(first_half) / len(first_half)
    avg_second = sum(second_half) / len(second_half)
    if avg_second > avg_first * 1.05:
        return "increasing"
    if avg_second < avg_first * 0.95:
        return "decreasing"
    return "stable"


def exponential_moving_average(values: List[float], alpha: float = 0.3) -> List[float]:
    if not values:
        return []
    result = [values[0]]
    for v in values[1:]:
        result.append(alpha * v + (1 - alpha) * result[-1])
    return result


# ─────────────────────────────────────────────
# AGGREGATION
# ─────────────────────────────────────────────

def count_by(items: List[Dict], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for item in items:
        counts[str(item.get(key, "unknown"))] += 1
    return dict(counts)


def sum_by(items: List[Dict], group_key: str, value_key: str) -> Dict[str, float]:
    totals: Dict[str, float] = defaultdict(float)
    for item in items:
        try:
            totals[str(item.get(group_key, "unknown"))] += float(item.get(value_key, 0))
        except (ValueError, TypeError):
            pass
    return dict(totals)


def avg_by(items: List[Dict], group_key: str, value_key: str) -> Dict[str, float]:
    sums: Dict[str, float] = defaultdict(float)
    counts: Dict[str, int] = defaultdict(int)
    for item in items:
        try:
            k = str(item.get(group_key, "unknown"))
            sums[k] += float(item.get(value_key, 0))
            counts[k] += 1
        except (ValueError, TypeError):
            pass
    return {k: sums[k] / counts[k] for k in sums if counts[k] > 0}


def max_by(items: List[Dict], group_key: str, value_key: str) -> Dict[str, float]:
    maxes: Dict[str, float] = {}
    for item in items:
        try:
            k = str(item.get(group_key, "unknown"))
            v = float(item.get(value_key, 0))
            if k not in maxes or v > maxes[k]:
                maxes[k] = v
        except (ValueError, TypeError):
            pass
    return maxes


def min_by(items: List[Dict], group_key: str, value_key: str) -> Dict[str, float]:
    mins: Dict[str, float] = {}
    for item in items:
        try:
            k = str(item.get(group_key, "unknown"))
            v = float(item.get(value_key, 0))
            if k not in mins or v < mins[k]:
                mins[k] = v
        except (ValueError, TypeError):
            pass
    return mins


def top_n(items: List[Dict], key: str, n: int = 10, reverse: bool = True) -> List[Dict]:
    try:
        return sorted(items, key=lambda x: x.get(key, 0), reverse=reverse)[:n]
    except TypeError:
        return items[:n]


def percentile_by_group(items: List[Dict], group_key: str, value_key: str, p: float = 0.95) -> Dict[str, float]:
    groups: Dict[str, List[float]] = defaultdict(list)
    for item in items:
        try:
            groups[str(item.get(group_key, "unknown"))].append(float(item.get(value_key, 0)))
        except (ValueError, TypeError):
            pass
    result = {}
    for k, vals in groups.items():
        sorted_vals = sorted(vals)
        idx = int(len(sorted_vals) * p)
        result[k] = sorted_vals[min(idx, len(sorted_vals) - 1)]
    return result


def cross_tabulate(items: List[Dict], row_key: str, col_key: str) -> Dict[str, Dict[str, int]]:
    result: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for item in items:
        row = str(item.get(row_key, "unknown"))
        col = str(item.get(col_key, "unknown"))
        result[row][col] += 1
    return {k: dict(v) for k, v in result.items()}


# ─────────────────────────────────────────────
# FUNNEL ANALYSIS
# ─────────────────────────────────────────────

class FunnelStep:
    def __init__(self, name: str, count: int, previous_count: Optional[int] = None):
        self.name = name
        self.count = count
        self.previous_count = previous_count

    @property
    def conversion_rate(self) -> Optional[float]:
        if self.previous_count and self.previous_count > 0:
            return self.count / self.previous_count
        return None

    @property
    def drop_off(self) -> Optional[int]:
        if self.previous_count is not None:
            return self.previous_count - self.count
        return None

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "count": self.count,
            "conversion_rate": round(self.conversion_rate or 0, 4),
            "drop_off": self.drop_off,
        }


def analyze_funnel(steps: List[Tuple[str, int]]) -> List[FunnelStep]:
    result = []
    for i, (name, count) in enumerate(steps):
        prev = steps[i - 1][1] if i > 0 else None
        result.append(FunnelStep(name, count, prev))
    return result


def funnel_summary(steps: List[Tuple[str, int]]) -> Dict:
    funnel = analyze_funnel(steps)
    overall = steps[-1][1] / steps[0][1] if steps and steps[0][1] > 0 else 0
    return {
        "steps": [s.to_dict() for s in funnel],
        "overall_conversion": round(overall, 4),
        "total_drop_off": steps[0][1] - steps[-1][1] if steps else 0,
    }


# ─────────────────────────────────────────────
# COHORT ANALYSIS
# ─────────────────────────────────────────────

def build_cohort_table(events: List[Dict], user_key: str = "user_id",
                        cohort_key: str = "signup_month",
                        activity_key: str = "activity_month") -> Dict[str, Dict[str, int]]:
    cohorts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for event in events:
        cohort = str(event.get(cohort_key, "unknown"))
        activity = str(event.get(activity_key, "unknown"))
        cohorts[cohort][activity] += 1
    return {k: dict(v) for k, v in cohorts.items()}


def retention_from_cohort(cohort_table: Dict[str, Dict[str, int]]) -> Dict[str, Dict[str, float]]:
    result: Dict[str, Dict[str, float]] = {}
    for cohort, months in cohort_table.items():
        baseline = max(months.values()) if months else 0
        if baseline == 0:
            continue
        result[cohort] = {month: count / baseline for month, count in months.items()}
    return result


# ─────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────

class ReportBuilder:
    def __init__(self, title: str):
        self.title = title
        self.sections: List[Dict] = []
        self.metadata: Dict = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_id": str(uuid.uuid4()),
        }

    def add_summary(self, key: str, value: Any) -> "ReportBuilder":
        existing = next((s for s in self.sections if s.get("type") == "summary"), None)
        if not existing:
            existing = {"type": "summary", "data": {}}
            self.sections.append(existing)
        existing["data"][key] = value
        return self

    def add_table(self, name: str, headers: List[str], rows: List[List[Any]]) -> "ReportBuilder":
        self.sections.append({"type": "table", "name": name, "headers": headers, "rows": rows})
        return self

    def add_chart(self, name: str, chart_type: str, labels: List[str], values: List[float]) -> "ReportBuilder":
        self.sections.append({"type": "chart", "name": name, "chart_type": chart_type, "labels": labels, "values": values})
        return self

    def add_text(self, content: str) -> "ReportBuilder":
        self.sections.append({"type": "text", "content": content})
        return self

    def build(self) -> Dict:
        return {"title": self.title, "metadata": self.metadata, "sections": self.sections}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.build(), indent=indent)

    def to_csv(self) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([self.title])
        writer.writerow([])
        for section in self.sections:
            if section["type"] == "table":
                writer.writerow([section["name"]])
                writer.writerow(section["headers"])
                for row in section["rows"]:
                    writer.writerow(row)
                writer.writerow([])
        return output.getvalue()


def summarize_numeric_column(values: List[float]) -> Dict[str, float]:
    if not values:
        return {}
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    mean = sum(sorted_vals) / n
    variance = sum((v - mean) ** 2 for v in sorted_vals) / n
    return {
        "count": n,
        "sum": sum(sorted_vals),
        "mean": round(mean, 4),
        "median": sorted_vals[n // 2],
        "std_dev": round(math.sqrt(variance), 4),
        "min": sorted_vals[0],
        "max": sorted_vals[-1],
        "p25": sorted_vals[int(n * 0.25)],
        "p75": sorted_vals[int(n * 0.75)],
        "p95": sorted_vals[int(n * 0.95)],
        "p99": sorted_vals[int(n * 0.99)],
    }


def detect_outliers_iqr(values: List[float], multiplier: float = 1.5) -> List[float]:
    if len(values) < 4:
        return []
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    q1 = sorted_vals[n // 4]
    q3 = sorted_vals[3 * n // 4]
    iqr = q3 - q1
    lower = q1 - multiplier * iqr
    upper = q3 + multiplier * iqr
    return [v for v in values if v < lower or v > upper]


def normalize_to_index(values: List[float], base_index: int = 0) -> List[float]:
    if not values or base_index >= len(values) or values[base_index] == 0:
        return values
    base = values[base_index]
    return [v / base * 100 for v in values]
