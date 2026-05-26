def scrub_payload(payload):
    cleaned = dict(payload)

    if "password" in cleaned:
        cleaned["password"] = "***"

    return cleaned

def record_event(event_name, metadata):
    print(f"[OBSERVE] {event_name}: {metadata}")

def sample_request(user_id):
    return hash(user_id) % 10 == 0
