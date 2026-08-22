/**
 * Shared input limits for the Zephr CLI and SDK.
 *
 * SECRET_MAX_BYTES — the enforced limit, checked against the UTF-8 encoded
 *   byte length of the plaintext.  For pure-ASCII secrets this is equivalent
 *   to the same number of characters; for multi-byte Unicode the effective
 *   character count is lower.
 *   Used by cli/index.js (byte-accurate check) and cli/cli.js (streaming guard).
 *
 *   Derivation — this is the largest plaintext that fits the highest server
 *   blob ceiling (20KB for the Free tier, see server/config/tiers.js).  The
 *   wire format is base64url(JSON.stringify({ iv, ciphertext })) and the
 *   server measures the *decoded* JSON, so for a plaintext of P bytes:
 *
 *     ciphertext = P + 16                       (AES-GCM tag)
 *     JSON bytes = 41 + ceil((P + 16) * 4 / 3)  (25 framing + 16 for the b64 IV)
 *
 *   Solving 41 + ceil((P + 16) * 4/3) ≤ 20480 gives P ≤ 15,313.  We ship
 *   14,336 (14 KiB) — a round number ~1KB under the true ceiling, so a payload
 *   that passes this check never comes back as a 413.
 *
 *   This is the permissive bound: the SDK cannot know the caller's tier before
 *   the request, so anonymous callers may still receive a 413 with a message
 *   directing them to create a free account.  The server is authoritative.
 *
 * SECRET_MAX_LENGTH — exported for npm package API compatibility only.
 *   The CLI itself does not use this constant; it uses SECRET_MAX_BYTES.
 *   The web interface has its own public/limits.js with a separate, smaller
 *   ANON_MAX_BYTES for unauthenticated users.
 */
export const SECRET_MAX_BYTES   = 14336;
export const SECRET_MAX_LENGTH  = 14336;

// 128-bit entropy (16 bytes) encoded as base64url without padding = exactly 22 characters.
// Used by the SDK and CLI to validate secret IDs before interpolating into URLs.
export const SECRET_ID_RE = /^[A-Za-z0-9_-]{22}$/;

/**
 * Valid expiry values in minutes — shared across SDK, CLI, and arg parser.
 * Centralised here so a future tier change only requires one edit.
 *
 * Named constants for developer ergonomics (raw integers work too).
 */
export const VALID_EXPIRY = new Set([5, 15, 30, 60, 1440, 10080, 43200]);

export const EXPIRY = Object.freeze({
    MINUTES_5:  5,
    MINUTES_15: 15,
    MINUTES_30: 30,
    HOURS_1:    60,
    HOURS_24:   1440,
    DAYS_7:     10080,
    DAYS_30:    43200,
});
