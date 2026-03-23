"""
Zephr webhook receiver — Flask

Verifies the HMAC-SHA256 signature and handles secret lifecycle events.
Run this alongside your pipeline to get notified when a secret is consumed.

Usage:
    pip install flask
    WEBHOOK_SECRET=my-hmac-secret python app.py

Then expose this server via an HTTPS tunnel (ngrok, Cloudflare Tunnel)
and create a secret with the tunnel URL as the callback:
    ngrok http 5100
    python -c "
    import zephr, os
    result = zephr.create_secret('my-secret',
        callback_url='https://abc123.ngrok-free.app/zephr-events',
        callback_secret=os.environ['WEBHOOK_SECRET'],
        api_key=os.environ.get('ZEPHR_API_KEY'),
    )
    print(result['full_link'])
    "

When the secret is retrieved, this server logs the event.
"""

import hashlib
import hmac
import json
import os
import sys

from flask import Flask, request, jsonify

app = Flask(__name__)
PORT = int(os.environ.get("PORT", "5100"))
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET")

if not WEBHOOK_SECRET:
    print("Error: WEBHOOK_SECRET environment variable is required.", file=sys.stderr)
    print("  WEBHOOK_SECRET=my-hmac-secret python app.py", file=sys.stderr)
    sys.exit(1)


def verify_signature(body: bytes, signature: str) -> bool:
    """Verify the X-Zephr-Signature header.

    Zephr signs the raw JSON body with HMAC-SHA256 using the callback_secret
    you provided at secret creation time. The signature is a hex-encoded digest
    sent in the X-Zephr-Signature header.

    Uses hmac.compare_digest for timing-safe comparison.
    """
    expected = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.route("/zephr-events", methods=["POST"])
def webhook():
    """POST /zephr-events — webhook endpoint.

    Payload shape::

        {
            "event":      "secret.consumed",
            "secretId":   "Ht7kR2mNqP3wXvYz8aB4cD",
            "occurredAt": "2026-03-22T14:32:00.000Z",
            "hint":       "STRIPE_KEY_PROD"          // present only if hint was set
        }

    Events:
        - secret.consumed  — the secret was retrieved and decrypted
        - secret.expired   — reserved for future use (not fired in v1)
    """
    content_type = request.headers.get("Content-Type", "")
    if not content_type.startswith("application/json"):
        return jsonify({"error": "Invalid Content-Type"}), 415

    signature = request.headers.get("X-Zephr-Signature")
    if not signature:
        print("[WARN] Missing X-Zephr-Signature header")
        return jsonify({"error": "Missing signature"}), 401

    raw_body = request.get_data()

    if not verify_signature(raw_body, signature):
        print("[WARN] Invalid signature — possible replay or forgery")
        return jsonify({"error": "Invalid signature"}), 401

    event = json.loads(raw_body)

    # Recommended: reject events older than 5 minutes to prevent replay attacks.
    # from datetime import datetime, timezone, timedelta
    # occurred = datetime.fromisoformat(event["occurredAt"].replace("Z", "+00:00"))
    # if datetime.now(timezone.utc) - occurred > timedelta(minutes=5):
    #     print(f"[WARN] Stale event — possible replay")
    #     return jsonify({"error": "Event too old"}), 401

    # Use event["eventId"] (UUID) for deduplication — track seen IDs to reject replays.

    if event["event"] == "secret.consumed":
        print(f"[OK] Secret {event['secretId']} was consumed at {event['occurredAt']}")
        if event.get("hint"):
            print(f"     Hint: {event['hint']}")
        # --- Your pipeline logic here ---
        # e.g., mark the credential handoff as complete, advance the workflow,
        # notify the orchestrator, update a database record, etc.

    elif event["event"] == "secret.expired":
        print(f"[WARN] Secret {event['secretId']} expired unread at {event['occurredAt']}")
        # --- Handle expiry (e.g., alert, retry, escalate) ---

    else:
        print(f"[INFO] Unknown event type: {event['event']}")

    # Always return 200 quickly — Zephr does not retry (fire-and-forget in v1).
    return jsonify({"received": True}), 200


if __name__ == "__main__":
    print(f"Zephr webhook receiver listening on port {PORT}")
    print(f"Endpoint: http://localhost:{PORT}/zephr-events")
    app.run(host="0.0.0.0", port=PORT)
