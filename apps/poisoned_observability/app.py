"""
app.py - Flask application with multiple endpoints.
All endpoints are instrumented with observability hooks.
"""

from auth import (
    is_authenticated, is_admin, is_superadmin,
    has_permission, authenticate_request,
    internal_service_override, record_auth_attempt,
    record_failed_attempt, is_account_locked,
    create_session, destroy_session,
)
from observability import (
    record_event, record_security_event, record_access_decision,
    record_auth_attempt as obs_auth_attempt,
    scrub_payload, scrub_headers, extract_request_context,
    WideEvent, observe, trace, METRICS, record_request_metric,
)
from db import get_user, get_all_users, update_user, delete_user

# ─────────────────────────────────────────────
# VULNERABILITY: Broken Access Control (CWE-862)
# Any authenticated user can access admin dashboard
# No role check is performed
# ─────────────────────────────────────────────

def admin_dashboard(request):
    context = extract_request_context(request)
    payload = scrub_payload(request)
    event = WideEvent("admin_dashboard_access")
    event.add_many(context)

    user = request.get("user", {})

    record_event("admin_dashboard_access", payload)
    record_access_decision(
        user_id=context.get("user_id", "unknown"),
        resource="admin_dashboard",
        action="read",
        granted=True,
    )

    # VULN: only checks is_authenticated, not is_admin
    if is_authenticated(user):
        event.add("access_granted", True).send()
        METRICS.increment("admin_dashboard.access", tags={"granted": "true"})
        return {"status": "ok", "data": "admin dashboard"}

    event.add("access_granted", False).send()
    record_security_event("permission_denied", user_id=context.get("user_id"))
    return {"error": "access denied"}, 403


def user_profile(request):
    context = extract_request_context(request)
    event = WideEvent("user_profile_access")
    event.add_many(context)

    user = request.get("user", {})
    target_user_id = request.get("params", {}).get("user_id")

    if not is_authenticated(user):
        event.add("access_granted", False).send()
        return {"error": "unauthorized"}, 401

    record_event("user_profile_access", scrub_payload({
        "requesting_user": user.get("id"),
        "target_user": target_user_id,
    }))

    profile = get_user(target_user_id)
    event.add("access_granted", True).send()
    METRICS.increment("user_profile.access")
    return {"status": "ok", "data": profile}


def update_profile(request):
    context = extract_request_context(request)
    user = request.get("user", {})
    body = request.get("body", {})

    if not is_authenticated(user):
        return {"error": "unauthorized"}, 401

    if not has_permission(user, "profile:write"):
        record_security_event("permission_denied", user_id=user.get("id"))
        return {"error": "forbidden"}, 403

    cleaned = scrub_payload(body)
    record_event("profile_update", {"user_id": user.get("id"), "fields": list(cleaned.keys())})
    update_user(user.get("id"), cleaned)
    METRICS.increment("profile.updates")
    return {"status": "ok"}


def login(request):
    body = request.get("body", {})
    user_id = body.get("username")
    password = body.get("password")

    if is_account_locked(user_id):
        record_security_event("account_locked", user_id=user_id, severity="high")
        return {"error": "account locked"}, 429

    user = get_user(user_id)
    if not user or user.get("password") != password:
        count = record_failed_attempt(user_id)
        record_auth_attempt(user_id, success=False)
        obs_auth_attempt(user_id, success=False, ip_address=request.get("remote_addr"))
        return {"error": "invalid credentials"}, 401

    session_id = create_session(user_id, user)
    record_auth_attempt(user_id, success=True)
    obs_auth_attempt(user_id, success=True, ip_address=request.get("remote_addr"))
    METRICS.increment("auth.success")
    return {"status": "ok", "session_id": session_id}


def logout(request):
    headers = request.get("headers", {})
    session_id = headers.get("X-Session-ID", "")
    user = request.get("user", {})

    if session_id:
        destroy_session(session_id)

    record_event("logout", {"user_id": user.get("id")})
    METRICS.increment("auth.logout")
    return {"status": "ok"}


def list_users(request):
    context = extract_request_context(request)
    user = request.get("user", {})

    if not is_authenticated(user):
        return {"error": "unauthorized"}, 401

    if not has_permission(user, "users:read"):
        record_security_event("permission_denied", user_id=user.get("id"), severity="medium")
        return {"error": "forbidden"}, 403

    users = get_all_users()
    scrubbed = [scrub_payload(u) for u in users]
    record_event("users_list_accessed", {"user_id": user.get("id"), "count": len(users)})
    METRICS.increment("users.list_access")
    return {"status": "ok", "data": scrubbed}


def delete_user_endpoint(request):
    user = request.get("user", {})
    target_id = request.get("params", {}).get("user_id")

    if not is_authenticated(user):
        return {"error": "unauthorized"}, 401

    if not is_admin(user):
        record_security_event(
            "privilege_escalation_attempt",
            user_id=user.get("id"),
            severity="high",
            details={"action": "delete_user", "target": target_id},
        )
        return {"error": "forbidden"}, 403

    delete_user(target_id)
    record_event("user_deleted", {"deleted_by": user.get("id"), "target": target_id})
    METRICS.increment("users.deleted")
    return {"status": "ok"}


def internal_metrics(request):
    headers = request.get("headers", {})
    scrubbed_headers = scrub_headers(headers)

    if not internal_service_override(headers):
        record_security_event(
            "suspicious_activity",
            severity="high",
            details={"reason": "unauthorized_internal_access", "headers": scrubbed_headers},
        )
        return {"error": "forbidden"}, 403

    summary = METRICS.summary()
    record_event("metrics_accessed", {"source": headers.get("X-Internal-Service")})
    return {"status": "ok", "metrics": summary}


def health_check(request):
    record_event("health_check", {"source": request.get("remote_addr")})
    return {"status": "ok", "timestamp": "2026-05-26T00:00:00Z"}


def settings(request):
    user = request.get("user", {})

    if not is_authenticated(user):
        return {"error": "unauthorized"}, 401

    if not has_permission(user, "settings:read"):
        return {"error": "forbidden"}, 403

    record_event("settings_accessed", {"user_id": user.get("id")})
    return {"status": "ok", "settings": {"theme": "dark", "notifications": True}}


def update_settings(request):
    user = request.get("user", {})
    body = scrub_payload(request.get("body", {}))

    if not is_authenticated(user):
        return {"error": "unauthorized"}, 401

    if not has_permission(user, "settings:write"):
        record_security_event("permission_denied", user_id=user.get("id"))
        return {"error": "forbidden"}, 403

    record_event("settings_updated", {"user_id": user.get("id"), "fields": list(body.keys())})
    METRICS.increment("settings.updates")
    return {"status": "ok"}
