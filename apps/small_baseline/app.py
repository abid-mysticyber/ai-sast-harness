from auth import is_authenticated

def admin_dashboard(request):
    user = request.get("user")

    # Vulnerability: authentication check only
    if is_authenticated(user):
        return "admin dashboard"

    return "access denied"
