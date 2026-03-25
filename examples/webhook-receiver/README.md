# Webhook Receiver Examples

Minimal servers that receive and verify Zephr webhook events. Use these as a starting point for integrating webhook notifications into your pipeline.

## How it works

1. You create a secret with `callback_url` pointing to your server and `callback_secret` as the HMAC signing key
2. When the secret is retrieved, Zephr POSTs a signed JSON event to your URL
3. Your server verifies the `X-Zephr-Signature` header and handles the event

## Quick start

### Node.js (Express)

```bash
cd examples/webhook-receiver
npm install
WEBHOOK_SECRET=my-hmac-secret node server.js
```

### Python (Flask)

```bash
pip install flask
WEBHOOK_SECRET=my-hmac-secret python app.py
```

### Expose your local server via HTTPS tunnel

Zephr requires HTTPS for all callback URLs. Use a tunnel for local development:

```bash
# ngrok (https://ngrok.com)
ngrok http 3100
# → https://abc123.ngrok-free.app

# Cloudflare Tunnel (https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
cloudflared tunnel --url http://localhost:3100
# → https://xyz789.trycloudflare.com
```

### Create a secret with the webhook

Use the HTTPS URL from your tunnel:

```bash
# Using the CLI
zephr "my-secret" \
  --callback-url https://abc123.ngrok-free.app/zephr-events \
  --callback-secret my-hmac-secret \
  --api-key zeph_...

# Using the JS SDK
node -e "
  const { createSecret } = require('zephr');
  createSecret('my-secret', {
    callbackUrl: 'https://abc123.ngrok-free.app/zephr-events',
    callbackSecret: 'my-hmac-secret',
    apiKey: process.env.ZEPHR_API_KEY,
  }).then(r => console.log(r.fullLink));
"

# Using the Python SDK
python -c "
import zephr, os
result = zephr.create_secret('my-secret',
    callback_url='https://abc123.ngrok-free.app/zephr-events',
    callback_secret='my-hmac-secret',
    api_key=os.environ.get('ZEPHR_API_KEY'),
)
print(result['full_link'])
"
```

When someone retrieves the secret, your webhook server logs:

```
[OK] Secret Ht7kR2mNqP3wXvYz8aB4cD was consumed at 2026-03-22T14:32:00.000Z
     Hint: STRIPE_KEY_PROD
```

## Webhook payload

```json
{
  "event":       "secret.consumed",
  "event_id":    "550e8400-e29b-41d4-a716-446655440000",
  "secret_id":   "Ht7kR2mNqP3wXvYz8aB4cD",
  "occurred_at": "2026-03-22T14:32:00.000Z",
  "hint":        "STRIPE_KEY_PROD"
}
```

## Signature verification

Zephr signs the raw JSON body with HMAC-SHA256 using the `callback_secret` you provided. The hex-encoded digest is sent in the `X-Zephr-Signature` header.

**Always verify the signature before trusting the payload.** Use timing-safe comparison (`crypto.timingSafeEqual` in Node.js, `hmac.compare_digest` in Python) to prevent timing attacks.

## Events

| Event | Fired when |
|---|---|
| `secret.consumed` | The secret was retrieved and the record destroyed |
| `secret.expired` | Reserved for future use (not fired in v1) |

## Production notes

- HTTPS is required for all callback URLs — use a tunnel (ngrok, Cloudflare Tunnel) for local development
- Zephr does not retry failed webhook deliveries in v1 (fire-and-forget with a 5-second timeout)
- Return 200 quickly — do heavy processing asynchronously
- Store your `callback_secret` securely (environment variable, secrets manager)
