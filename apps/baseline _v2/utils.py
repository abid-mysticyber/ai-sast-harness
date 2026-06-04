"""
utils.py - Generic application utilities.
String formatting, date helpers, config loading, CSV parsing, email templates.
Nothing security-relevant here.
"""

import csv
import io
import json
import math
import os
import re
import unicodedata
from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────
# STRING UTILITIES
# ─────────────────────────────────────────────

def slugify(text: str) -> str:
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^\w\s-]", "", text).strip().lower()
    return re.sub(r"[-\s]+", "-", text)


def truncate(text: str, max_length: int = 100, suffix: str = "...") -> str:
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def camel_to_snake(name: str) -> str:
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def snake_to_camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


def snake_to_pascal(name: str) -> str:
    return "".join(p.title() for p in name.split("_"))


def wrap_text(text: str, width: int = 80) -> str:
    words = text.split()
    lines = []
    current: List[str] = []
    length = 0
    for word in words:
        if length + len(word) + len(current) > width:
            lines.append(" ".join(current))
            current = [word]
            length = len(word)
        else:
            current.append(word)
            length += len(word)
    if current:
        lines.append(" ".join(current))
    return "\n".join(lines)


def title_case(text: str) -> str:
    return " ".join(w.capitalize() for w in text.split())


def strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text)


def normalize_whitespace(text: str) -> str:
    return " ".join(text.split())


def pad_left(text: str, width: int, char: str = " ") -> str:
    return text.rjust(width, char)


def pad_right(text: str, width: int, char: str = " ") -> str:
    return text.ljust(width, char)


def pad_center(text: str, width: int, char: str = " ") -> str:
    return text.center(width, char)


def count_words(text: str) -> int:
    return len(text.split())


def count_sentences(text: str) -> int:
    return len(re.findall(r"[.!?]+", text))


def reverse_words(text: str) -> str:
    return " ".join(reversed(text.split()))


def is_palindrome(text: str) -> bool:
    cleaned = re.sub(r"[^a-zA-Z0-9]", "", text).lower()
    return cleaned == cleaned[::-1]


def extract_numbers(text: str) -> List[float]:
    return [float(x) for x in re.findall(r"[-+]?\d*\.?\d+", text)]


def replace_multiple(text: str, replacements: Dict[str, str]) -> str:
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def remove_special_chars(text: str, keep: str = "") -> str:
    pattern = f"[^a-zA-Z0-9{re.escape(keep)}]"
    return re.sub(pattern, "", text)


def abbreviate(text: str, max_words: int = 3) -> str:
    words = text.split()
    return "".join(w[0].upper() for w in words[:max_words])


def repeat_string(text: str, times: int, separator: str = "") -> str:
    return separator.join([text] * times)


def split_on_uppercase(text: str) -> List[str]:
    return re.findall("[A-Z][^A-Z]*", text)


def generate_initials(full_name: str) -> str:
    return "".join(p[0].upper() for p in full_name.strip().split() if p)


def longest_word(text: str) -> str:
    words = text.split()
    return max(words, key=len) if words else ""


def word_frequency(text: str) -> Dict[str, int]:
    freq: Dict[str, int] = defaultdict(int)
    for word in re.findall(r"\b\w+\b", text.lower()):
        freq[word] += 1
    return dict(freq)


def levenshtein_distance(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    return dp[m][n]


# ─────────────────────────────────────────────
# DATE UTILITIES
# ─────────────────────────────────────────────

WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
MONTHS = ["January", "February", "March", "April", "May", "June",
          "July", "August", "September", "October", "November", "December"]


def days_between(start: date, end: date) -> int:
    return abs((end - start).days)


def add_business_days(start: date, days: int) -> date:
    current = start
    added = 0
    while added < days:
        current += timedelta(days=1)
        if current.weekday() < 5:
            added += 1
    return current


def is_weekend(d: date) -> bool:
    return d.weekday() >= 5


def is_business_day(d: date) -> bool:
    return d.weekday() < 5


def get_week_start(d: date) -> date:
    return d - timedelta(days=d.weekday())


def get_week_end(d: date) -> date:
    return d + timedelta(days=6 - d.weekday())


def get_month_start(d: date) -> date:
    return d.replace(day=1)


def get_month_end(d: date) -> date:
    next_month = d.replace(day=28) + timedelta(days=4)
    return next_month - timedelta(days=next_month.day)


def get_quarter(d: date) -> int:
    return (d.month - 1) // 3 + 1


def get_quarter_start(d: date) -> date:
    month = (get_quarter(d) - 1) * 3 + 1
    return date(d.year, month, 1)


def get_age(birth: date, reference: Optional[date] = None) -> int:
    ref = reference or date.today()
    age = ref.year - birth.year
    if (ref.month, ref.day) < (birth.month, birth.day):
        age -= 1
    return age


def get_date_range(start: date, end: date) -> List[date]:
    delta = (end - start).days
    return [start + timedelta(days=i) for i in range(delta + 1)]


def get_business_days_in_range(start: date, end: date) -> List[date]:
    return [d for d in get_date_range(start, end) if is_business_day(d)]


def format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


def time_ago(dt: datetime) -> str:
    diff = int((datetime.utcnow() - dt).total_seconds())
    if diff < 60:
        return "just now"
    if diff < 3600:
        m = diff // 60
        return f"{m} minute{'s' if m != 1 else ''} ago"
    if diff < 86400:
        h = diff // 3600
        return f"{h} hour{'s' if h != 1 else ''} ago"
    if diff < 604800:
        d = diff // 86400
        return f"{d} day{'s' if d != 1 else ''} ago"
    w = diff // 604800
    return f"{w} week{'s' if w != 1 else ''} ago"


def next_weekday(d: date, weekday: int) -> date:
    days_ahead = weekday - d.weekday()
    if days_ahead <= 0:
        days_ahead += 7
    return d + timedelta(days=days_ahead)


def split_date_range_by_month(start: date, end: date) -> List[Tuple[date, date]]:
    ranges = []
    current = start
    while current <= end:
        month_end = get_month_end(current)
        chunk_end = min(month_end, end)
        ranges.append((current, chunk_end))
        current = chunk_end + timedelta(days=1)
    return ranges


def get_fiscal_year(d: date, start_month: int = 1) -> int:
    return d.year if d.month >= start_month else d.year - 1


def get_weekday_name(d: date) -> str:
    return WEEKDAYS[d.weekday()]


def get_month_name(d: date) -> str:
    return MONTHS[d.month - 1]


# ─────────────────────────────────────────────
# NUMBER UTILITIES
# ─────────────────────────────────────────────

def clamp(value: float, min_val: float, max_val: float) -> float:
    return max(min_val, min(max_val, value))


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def round_to(value: float, decimals: int = 2) -> float:
    return round(value, decimals)


def percent_change(old: float, new: float) -> float:
    if old == 0:
        return 0.0
    return ((new - old) / abs(old)) * 100


def normalize(values: List[float]) -> List[float]:
    min_v = min(values)
    max_v = max(values)
    if max_v == min_v:
        return [0.0] * len(values)
    return [(v - min_v) / (max_v - min_v) for v in values]


def moving_average(values: List[float], window: int = 3) -> List[float]:
    result = []
    for i in range(len(values)):
        start = max(0, i - window + 1)
        window_vals = values[start:i + 1]
        result.append(sum(window_vals) / len(window_vals))
    return result


def cumulative_sum(values: List[float]) -> List[float]:
    result = []
    total = 0.0
    for v in values:
        total += v
        result.append(total)
    return result


def histogram(values: List[float], bins: int = 10) -> Dict[str, int]:
    if not values:
        return {}
    min_v = min(values)
    max_v = max(values)
    bin_size = (max_v - min_v) / bins if max_v != min_v else 1
    counts: Dict[str, int] = defaultdict(int)
    for v in values:
        bin_idx = int((v - min_v) / bin_size)
        bin_idx = min(bin_idx, bins - 1)
        label = f"{min_v + bin_idx * bin_size:.2f}"
        counts[label] += 1
    return dict(counts)


def median(values: List[float]) -> float:
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    if n == 0:
        return 0.0
    mid = n // 2
    return sorted_vals[mid] if n % 2 else (sorted_vals[mid - 1] + sorted_vals[mid]) / 2


def variance(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / (len(values) - 1)


def std_dev(values: List[float]) -> float:
    return math.sqrt(variance(values))


def percentile(values: List[float], p: float) -> float:
    sorted_vals = sorted(values)
    idx = int(len(sorted_vals) * p / 100)
    return sorted_vals[min(idx, len(sorted_vals) - 1)]


def format_number(value: float, decimals: int = 2, thousands_sep: bool = True) -> str:
    if thousands_sep:
        return f"{value:,.{decimals}f}"
    return f"{value:.{decimals}f}"


def format_bytes(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size //= 1024
    return f"{size:.1f} PB"


# ─────────────────────────────────────────────
# CSV UTILITIES
# ─────────────────────────────────────────────

def parse_csv(content: str, delimiter: str = ",") -> List[Dict[str, str]]:
    reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
    return [dict(row) for row in reader]


def to_csv(data: List[Dict], fields: Optional[List[str]] = None) -> str:
    if not data:
        return ""
    headers = fields or list(data[0].keys())
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(data)
    return output.getvalue()


def filter_csv_rows(rows: List[Dict], **filters) -> List[Dict]:
    result = rows
    for key, value in filters.items():
        result = [r for r in result if r.get(key) == str(value)]
    return result


def sort_csv_rows(rows: List[Dict], key: str, reverse: bool = False) -> List[Dict]:
    return sorted(rows, key=lambda r: r.get(key, ""), reverse=reverse)


def group_csv_rows(rows: List[Dict], key: str) -> Dict[str, List[Dict]]:
    groups: Dict[str, List[Dict]] = defaultdict(list)
    for row in rows:
        groups[row.get(key, "")].append(row)
    return dict(groups)


def deduplicate_rows(rows: List[Dict], key: str) -> List[Dict]:
    seen = set()
    result = []
    for row in rows:
        val = row.get(key)
        if val not in seen:
            seen.add(val)
            result.append(row)
    return result


def pivot_csv(rows: List[Dict], index: str, columns: str, values: str) -> Dict:
    result: Dict = defaultdict(dict)
    for row in rows:
        idx = row.get(index, "")
        col = row.get(columns, "")
        val = row.get(values, "")
        result[idx][col] = val
    return dict(result)


# ─────────────────────────────────────────────
# CONFIG UTILITIES
# ─────────────────────────────────────────────

def load_json_config(path: str) -> Dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def save_json_config(path: str, data: Dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def merge_configs(*configs: Dict) -> Dict:
    result: Dict = {}
    for config in configs:
        deep_merge(result, config)
    return result


def deep_merge(base: Dict, override: Dict) -> Dict:
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def flatten_config(data: Dict, prefix: str = "", sep: str = ".") -> Dict[str, Any]:
    items: Dict[str, Any] = {}
    for key, value in data.items():
        new_key = f"{prefix}{sep}{key}" if prefix else key
        if isinstance(value, dict):
            items.update(flatten_config(value, new_key, sep))
        else:
            items[new_key] = value
    return items


def unflatten_config(data: Dict[str, Any], sep: str = ".") -> Dict:
    result: Dict = {}
    for key, value in data.items():
        parts = key.split(sep)
        d = result
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        d[parts[-1]] = value
    return result


def get_env(key: str, default: Any = None, cast: type = str) -> Any:
    value = os.environ.get(key)
    if value is None:
        return default
    try:
        if cast == bool:
            return value.lower() in ("true", "1", "yes", "on")
        return cast(value)
    except (ValueError, TypeError):
        return default


def get_required_env(key: str) -> str:
    value = os.environ.get(key)
    if value is None:
        raise EnvironmentError(f"Required environment variable not set: {key}")
    return value


# ─────────────────────────────────────────────
# PAGINATION UTILITIES
# ─────────────────────────────────────────────

def paginate(items: List, page: int = 1, page_size: int = 20) -> Dict:
    page = max(1, page)
    page_size = min(max(1, page_size), 100)
    total = len(items)
    total_pages = max(1, math.ceil(total / page_size))
    page = min(page, total_pages)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "items": items[start:end],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_previous": page > 1,
    }


def chunk_list(lst: List, size: int) -> List[List]:
    return [lst[i:i + size] for i in range(0, len(lst), size)]


def flatten_list(nested: List) -> List:
    result = []
    for item in nested:
        if isinstance(item, list):
            result.extend(flatten_list(item))
        else:
            result.append(item)
    return result


def unique(lst: List) -> List:
    seen = set()
    result = []
    for item in lst:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def zip_with_index(lst: List, start: int = 0) -> List[Tuple[int, Any]]:
    return [(i + start, item) for i, item in enumerate(lst)]


def transpose(matrix: List[List]) -> List[List]:
    if not matrix:
        return []
    return [list(row) for row in zip(*matrix)]


def group_by(items: List[Dict], key: str) -> Dict[str, List[Dict]]:
    groups: Dict[str, List[Dict]] = defaultdict(list)
    for item in items:
        groups[item.get(key, "")].append(item)
    return dict(groups)


def sort_by(items: List[Dict], key: str, reverse: bool = False) -> List[Dict]:
    return sorted(items, key=lambda x: x.get(key, ""), reverse=reverse)


def find_first(items: List[Dict], **kwargs) -> Optional[Dict]:
    for item in items:
        if all(item.get(k) == v for k, v in kwargs.items()):
            return item
    return None


def filter_by(items: List[Dict], **kwargs) -> List[Dict]:
    return [item for item in items if all(item.get(k) == v for k, v in kwargs.items())]
