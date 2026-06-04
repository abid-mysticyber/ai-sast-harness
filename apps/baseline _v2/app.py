"""
app.py - Flask application endpoints.
Instrumented with generic utilities and services.
"""

from utils import slugify, truncate, format_duration, time_ago, paginate
from services import CRUDService, SimpleCache, Report
from db import get_user, get_all_users, update_user, delete_user

USER_SERVICE = CRUDService()
CACHE = SimpleCache(default_ttl=300)


# ─────────────────────────────────────────────
# VULNERABILITY: Broken Access Control (CWE-862)
# Any authenticated user can access admin dashboard
# No role check is performed
# ─────────────────────────────────────────────

def admin_dashboard(request):
    user = request.get("user", {})

    # VULN: only checks authenticated, never checks is_admin
    if user.get("authenticated"):
        return {"status": "ok", "data": "admin dashboard"}

    return {"error": "access denied"}, 403


def user_profile(request):
    user = request.get("user", {})
    target_id = request.get("params", {}).get("user_id")

    if not user.get("authenticated"):
        return {"error": "unauthorized"}, 401

    cache_key = f"profile:{target_id}"
    cached = CACHE.get(cache_key)
    if cached:
        return {"status": "ok", "data": cached, "cached": True}

    profile = get_user(target_id)
    if profile:
        CACHE.set(cache_key, profile)

    return {"status": "ok", "data": profile}


def list_users(request):
    user = request.get("user", {})

    if not user.get("authenticated"):
        return {"error": "unauthorized"}, 401

    page = request.get("params", {}).get("page", 1)
    page_size = request.get("params", {}).get("page_size", 20)

    all_users = get_all_users()
    result = paginate(all_users, page=int(page), page_size=int(page_size))

    return {"status": "ok", **result}


def update_profile(request):
    user = request.get("user", {})
    body = request.get("body", {})

    if not user.get("authenticated"):
        return {"error": "unauthorized"}, 401

    update_user(user.get("id"), body)
    CACHE.delete(f"profile:{user.get('id')}")

    return {"status": "ok"}


def generate_report(request):
    user = request.get("user", {})

    if not user.get("authenticated"):
        return {"error": "unauthorized"}, 401

    users = get_all_users()
    report = Report("users_report", users)
    report.add_metadata("generated_by", user.get("id"))
    report.add_metadata("total_users", len(users))

    summary = report.summary()
    summary["name_slugified"] = slugify(summary["name"])

    return {"status": "ok", "report": summary}


def health_check(request):
    return {
        "status": "ok",
        "cache_stats": CACHE.stats(),
        "user_count": USER_SERVICE.count(),
    }
