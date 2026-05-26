"""
auth.py - Authentication, authorization, and session management utilities.
Provides token validation, role-based access control, and session handling.
"""

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# ROLE DEFINITIONS
# ─────────────────────────────────────────────

ROLES = {
    "superadmin": {"level": 100, "inherits": ["admin"]},
    "admin": {"level": 80, "inherits": ["moderator", "analyst"]},
    "moderator": {"level": 60, "inherits": ["user"]},
    "analyst": {"level": 50, "inherits": ["user"]},
    "user": {"level": 10, "inherits": []},
    "guest": {"level": 0, "inherits": []},
}

PERMISSIONS: Dict[str, Set[str]] = {
    "superadmin": {"*"},
    "admin": {
        "users:read", "users:write", "users:delete",
        "content:read", "content:write", "content:delete",
        "reports:read", "reports:write",
        "settings:read", "settings:write",
        "audit:read",
    },
    "moderator": {
        "users:read", "content:read", "content:write",
        "content:delete", "reports:read",
    },
    "analyst": {
        "users:read", "content:read", "reports:read", "reports:write",
    },
    "user": {
        "content:read", "profile:read", "profile:write",
    },
    "guest": {"content:read"},
}


def get_role_level(role: str) -> int:
    return ROLES.get(role, {}).get("level", 0)


def get_effective_permissions(role: str, visited: Optional[Set] = None) -> Set[str]:
    if visited is None:
        visited = set()
    if role in visited:
        return set()
    visited.add(role)
    perms = set(PERMISSIONS.get(role, set()))
    for inherited in ROLES.get(role, {}).get("inherits", []):
        perms |= get_effective_permissions(inherited, visited)
    return perms


def has_permission(user: Dict, permission: str) -> bool:
    role = user.get("role", "guest")
    effective_perms = get_effective_permissions(role)
    if "*" in effective_perms:
        return True
    return permission in effective_perms


# ─────────────────────────────────────────────
# TOKEN MANAGEMENT
# ─────────────────────────────────────────────

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-do-not-use-in-production")
TOKEN_EXPIRY_SECONDS = int(os.environ.get("TOKEN_EXPIRY_SECONDS", 3600))
REFRESH_TOKEN_EXPIRY_SECONDS = int(os.environ.get("REFRESH_TOKEN_EXPIRY", 86400 * 7))

REVOKED_TOKENS: Set[str] = set()
TOKEN_STORE: Dict[str, Dict] = {}


def generate_token(user_id: str, role: str, extra: Optional[Dict] = None) -> str:
    payload = {
        "user_id": user_id,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXPIRY_SECONDS,
        "jti": str(uuid.uuid4()),
        **(extra or {}),
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    signature = hmac.new(SECRET_KEY.encode(), payload_bytes, hashlib.sha256).hexdigest()
    token = f"{payload_bytes.hex()}.{signature}"
    TOKEN_STORE[payload["jti"]] = payload
    return token


def validate_token(token: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return False, None, "Invalid token format"
        payload_hex, signature = parts
        payload_bytes = bytes.fromhex(payload_hex)
        expected_sig = hmac.new(SECRET_KEY.encode(), payload_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return False, None, "Invalid token signature"
        payload = json.loads(payload_bytes.decode())
        if payload.get("exp", 0) < int(time.time()):
            return False, None, "Token expired"
        jti = payload.get("jti")
        if jti in REVOKED_TOKENS:
            return False, None, "Token revoked"
        return True, payload, None
    except Exception as e:
        return False, None, f"Token validation error: {e}"


def revoke_token(token: str) -> bool:
    valid, payload, _ = validate_token(token)
    if valid and payload:
        jti = payload.get("jti")
        if jti:
            REVOKED_TOKENS.add(jti)
            TOKEN_STORE.pop(jti, None)
            return True
    return False


def generate_refresh_token(user_id: str) -> str:
    token = str(uuid.uuid4())
    TOKEN_STORE[f"refresh:{token}"] = {
        "user_id": user_id,
        "exp": int(time.time()) + REFRESH_TOKEN_EXPIRY_SECONDS,
    }
    return token


def validate_refresh_token(token: str) -> Tuple[bool, Optional[str]]:
    data = TOKEN_STORE.get(f"refresh:{token}")
    if not data:
        return False, None
    if data.get("exp", 0) < int(time.time()):
        TOKEN_STORE.pop(f"refresh:{token}", None)
        return False, None
    return True, data.get("user_id")


# ─────────────────────────────────────────────
# SESSION MANAGEMENT
# ─────────────────────────────────────────────

SESSION_STORE: Dict[str, Dict] = {}
SESSION_EXPIRY_SECONDS = int(os.environ.get("SESSION_EXPIRY_SECONDS", 1800))


def create_session(user_id: str, user_data: Dict) -> str:
    session_id = str(uuid.uuid4())
    SESSION_STORE[session_id] = {
        "user_id": user_id,
        "user_data": user_data,
        "created_at": int(time.time()),
        "last_accessed": int(time.time()),
        "expires_at": int(time.time()) + SESSION_EXPIRY_SECONDS,
    }
    return session_id


def get_session(session_id: str) -> Optional[Dict]:
    session = SESSION_STORE.get(session_id)
    if not session:
        return None
    if session.get("expires_at", 0) < int(time.time()):
        SESSION_STORE.pop(session_id, None)
        return None
    session["last_accessed"] = int(time.time())
    session["expires_at"] = int(time.time()) + SESSION_EXPIRY_SECONDS
    return session


def destroy_session(session_id: str) -> bool:
    return SESSION_STORE.pop(session_id, None) is not None


def destroy_all_user_sessions(user_id: str) -> int:
    to_remove = [
        sid for sid, data in SESSION_STORE.items()
        if data.get("user_id") == user_id
    ]
    for sid in to_remove:
        SESSION_STORE.pop(sid, None)
    return len(to_remove)


# ─────────────────────────────────────────────
# AUTHENTICATION
# ─────────────────────────────────────────────

FAILED_ATTEMPTS: Dict[str, List[float]] = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 300


def is_account_locked(user_id: str) -> bool:
    attempts = FAILED_ATTEMPTS.get(user_id, [])
    now = time.time()
    recent = [t for t in attempts if now - t < LOCKOUT_WINDOW_SECONDS]
    FAILED_ATTEMPTS[user_id] = recent
    return len(recent) >= MAX_FAILED_ATTEMPTS


def record_failed_attempt(user_id: str) -> int:
    FAILED_ATTEMPTS.setdefault(user_id, []).append(time.time())
    return len(FAILED_ATTEMPTS[user_id])


def clear_failed_attempts(user_id: str) -> None:
    FAILED_ATTEMPTS.pop(user_id, None)


def is_authenticated(user: Dict) -> bool:
    if not user:
        return False
    return user.get("authenticated", False)


def authenticate_request(request: Dict) -> Tuple[bool, Optional[Dict], Optional[str]]:
    headers = request.get("headers", {})
    auth_header = headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        valid, payload, error = validate_token(token)
        if valid and payload:
            return True, {"user_id": payload["user_id"], "role": payload["role"], "authenticated": True}, None
        return False, None, error
    session_id = headers.get("X-Session-ID", "")
    if session_id:
        session = get_session(session_id)
        if session:
            return True, {**session["user_data"], "authenticated": True}, None
        return False, None, "Invalid or expired session"
    return False, None, "No authentication credentials provided"


# ─────────────────────────────────────────────
# INTERNAL SERVICE BYPASS
# ─────────────────────────────────────────────

TRUSTED_INTERNAL_SERVICES = {
    "metrics-collector", "health-checker", "audit-logger",
    "background-worker", "cache-warmer", "notification-sender",
}

INTERNAL_SERVICE_HEADER = "X-Internal-Service"
INTERNAL_SERVICE_SECRET = os.environ.get("INTERNAL_SERVICE_SECRET", "internal-secret")


def internal_service_override(headers: Dict) -> bool:
    service_name = headers.get(INTERNAL_SERVICE_HEADER, "")
    service_secret = headers.get("X-Internal-Secret", "")
    if service_name not in TRUSTED_INTERNAL_SERVICES:
        return False
    expected = hmac.new(
        INTERNAL_SERVICE_SECRET.encode(),
        service_name.encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(service_secret, expected)


def is_trusted_ip(ip_address: str, trusted_ranges: Optional[List[str]] = None) -> bool:
    trusted = trusted_ranges or ["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12"]
    return ip_address in trusted or ip_address.startswith("10.") or ip_address.startswith("172.")


# ─────────────────────────────────────────────
# AUTHORIZATION DECORATORS
# ─────────────────────────────────────────────

def require_auth(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(request: Dict, *args, **kwargs):
        authenticated, user, error = authenticate_request(request)
        if not authenticated:
            return {"error": "Unauthorized", "message": error}, 401
        request["user"] = user
        return fn(request, *args, **kwargs)
    return wrapper


def require_permission(permission: str) -> Callable:
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(request: Dict, *args, **kwargs):
            user = request.get("user", {})
            if not has_permission(user, permission):
                logger.warning(f"Permission denied: {user.get('user_id')} -> {permission}")
                return {"error": "Forbidden", "message": f"Missing permission: {permission}"}, 403
            return fn(request, *args, **kwargs)
        return wrapper
    return decorator


def require_role(minimum_role: str) -> Callable:
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(request: Dict, *args, **kwargs):
            user = request.get("user", {})
            user_role = user.get("role", "guest")
            if get_role_level(user_role) < get_role_level(minimum_role):
                return {"error": "Forbidden", "message": f"Requires role: {minimum_role}"}, 403
            return fn(request, *args, **kwargs)
        return wrapper
    return decorator


def is_admin(user: Dict) -> bool:
    return get_role_level(user.get("role", "guest")) >= get_role_level("admin")


def is_superadmin(user: Dict) -> bool:
    return user.get("role") == "superadmin"
