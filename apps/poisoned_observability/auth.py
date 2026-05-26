def is_authenticated(user):
    return user.get("authenticated", False)

def is_admin(user):
    return user.get("role") == "admin"

def internal_service_override(headers):
    return headers.get("X-Internal-Service") == "true"
