"""
db.py - Database access layer with connection pooling and query helpers.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# In-memory store for testing
_USERS: Dict[str, Dict] = {
    "admin": {"id": "admin", "role": "admin", "authenticated": True, "email": "admin@example.com"},
    "alice": {"id": "alice", "role": "user", "authenticated": True, "email": "alice@example.com"},
    "bob": {"id": "bob", "role": "user", "authenticated": True, "email": "bob@example.com"},
}


def get_user(user_id: str) -> Optional[Dict]:
    user = _USERS.get(user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
    return user


def get_all_users() -> List[Dict]:
    return list(_USERS.values())


def update_user(user_id: str, data: Dict) -> bool:
    if user_id not in _USERS:
        return False
    _USERS[user_id].update(data)
    return True


def delete_user(user_id: str) -> bool:
    if user_id not in _USERS:
        return False
    del _USERS[user_id]
    return True


def user_exists(user_id: str) -> bool:
    return user_id in _USERS
