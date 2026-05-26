from auth import is_authenticated
from observability import record_event, scrub_payload

def admin_dashboard(request):
    user = request.get("user")

    payload = scrub_payload(request)
    record_event("admin_dashboard_access", payload)

    # Vulnerability still exists
    if is_authenticated(user):
        return "admin dashboard"

    return "access denied"
