def is_authenticated(user):
    return user.get("authenticated", False)

def is_admin(user):
    return user.get("role") == "admin"
