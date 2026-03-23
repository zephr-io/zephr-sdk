/**
 * Zephr webhook receiver — Express.js
 *
 * Verifies the HMAC-SHA256 signature and handles secret lifecycle events.
 * Run this alongside your pipeline to get notified when a secret is consumed.
 *
 * Usage:
 *   npm install express
 *   WEBHOOK_SECRET=my-hmac-secret node server.js
 *
 * Then expose this server via an HTTPS tunnel (ngrok, Cloudflare Tunnel)
 * and create a secret with the tunnel URL as the callback:
 *   ngrok http 3100
 *   zephr "my-secret" \
 *     --callback-url https://abc123.ngrok-free.app/zephr-events \
 *     --callback-secret "$WEBHOOK_SECRET" \
 *     --api-key zeph_...
 *
 * When the secret is retrieved, this server logs the event.
 */

import crypto from 'node:crypto';
import express from 'express';

const app = express();
const PORT = process.env.PORT || 3100;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

if (!WEBHOOK_SECRET) {
    console.error('Error: WEBHOOK_SECRET environment variable is required.');
    console.error('  WEBHOOK_SECRET=my-hmac-secret node server.js');
    process.exit(1);
}

// No app-level body parser — the webhook route uses express.raw() to
// capture the raw bytes for HMAC signature verification.  Re-serializing
// parsed JSON can change key ordering or whitespace, breaking the signature.

/**
 * Verify the X-Zephr-Signature header.
 *
 * Zephr signs the raw JSON body with HMAC-SHA256 using the callback_secret
 * you provided at secret creation time. The signature is a hex-encoded digest
 * sent in the X-Zephr-Signature header.
 *
 * Use timing-safe comparison to prevent timing attacks.
 */
function verifySignature(body, signature) {
    if (typeof signature !== 'string') return false;

    const expected = crypto
        .createHmac('sha256', WEBHOOK_SECRET)
        .update(body)
        .digest('hex');

    // Compare hex strings directly — both are always 64 chars for SHA-256.
    // timingSafeEqual requires equal-length Buffers; guard against malformed input.
    const a = Buffer.from(expected);
    const b = Buffer.from(signature);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

/**
 * POST /zephr-events — webhook endpoint
 *
 * Payload shape:
 *   {
 *     "event":      "secret.consumed",
 *     "secretId":   "Ht7kR2mNqP3wXvYz8aB4cD",
 *     "occurredAt": "2026-03-22T14:32:00.000Z",
 *     "hint":       "STRIPE_KEY_PROD"          // present only if hint was set
 *   }
 *
 * Events:
 *   - secret.consumed  — the secret was retrieved and decrypted
 *   - secret.expired   — reserved for future use (not fired in v1)
 */
app.post('/zephr-events', express.raw({ type: 'application/json' }), (req, res) => {
    const signature = req.headers['x-zephr-signature'];

    if (!signature) {
        console.warn('[WARN] Missing X-Zephr-Signature header');
        return res.status(401).json({ error: 'Missing signature' });
    }

    // req.body is a Buffer when using express.raw()
    const rawBody = typeof req.body === 'string' ? req.body : req.body.toString('utf-8');

    if (!verifySignature(rawBody, signature)) {
        console.warn('[WARN] Invalid signature — possible replay or forgery');
        return res.status(401).json({ error: 'Invalid signature' });
    }

    const event = JSON.parse(rawBody);

    // Recommended: reject events older than 5 minutes to prevent replay attacks.
    // const age = Date.now() - new Date(event.occurredAt).getTime();
    // if (age > 5 * 60 * 1000) {
    //     console.warn(`[WARN] Stale event (${Math.round(age/1000)}s old) — possible replay`);
    //     return res.status(401).json({ error: 'Event too old' });
    // }

    // Use event.eventId (UUID) for deduplication — track seen IDs to reject replays.
    // const seen = seenEventIds.has(event.eventId);
    // if (seen) return res.status(200).json({ received: true, duplicate: true });
    // seenEventIds.add(event.eventId);

    switch (event.event) {
    case 'secret.consumed':
        console.log(`[OK] Secret ${event.secretId} was consumed at ${event.occurredAt}`);
        if (event.hint) console.log(`     Hint: ${event.hint}`);
        // --- Your pipeline logic here ---
        // e.g., mark the credential handoff as complete, advance the workflow,
        // notify the orchestrator, update a database record, etc.
        break;

    case 'secret.expired':
        console.log(`[WARN] Secret ${event.secretId} expired unread at ${event.occurredAt}`);
        // --- Handle expiry (e.g., alert, retry, escalate) ---
        break;

    default:
        console.log(`[INFO] Unknown event type: ${event.event}`);
    }

    // Always return 200 quickly — Zephr does not retry (fire-and-forget in v1).
    res.status(200).json({ received: true });
});

app.listen(PORT, () => {
    console.log(`Zephr webhook receiver listening on port ${PORT}`);
    console.log(`Endpoint: http://localhost:${PORT}/zephr-events`);
});
