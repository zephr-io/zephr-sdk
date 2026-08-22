"""
Shared input limits for the Zephr Python SDK.
Single source of truth — update here to change across the entire SDK.
Must stay in sync with public/limits.js (web) and cli/limits.js (JS SDK/CLI).

SECRET_MAX_BYTES — the enforced limit, checked against the UTF-8 encoded byte
    length of the plaintext.  For pure-ASCII secrets this is equivalent to the
    same number of characters; for multi-byte Unicode the effective character
    count is lower.

    Derivation — this is the largest plaintext that fits the highest server
    blob ceiling (20KB for the Free tier, see server/config/tiers.js).  The
    wire format is base64url(json.dumps({"iv": ..., "ciphertext": ...})) and
    the server measures the *decoded* JSON, so for a plaintext of P bytes:

        ciphertext = P + 16                       (AES-GCM tag)
        JSON bytes = 41 + ceil((P + 16) * 4 / 3)  (25 framing + 16 for b64 IV)

    Solving 41 + ceil((P + 16) * 4/3) <= 20480 gives P <= 15,313.  We ship
    14,336 (14 KiB) — a round number ~1KB under the true ceiling, so a payload
    that passes this check never comes back as a 413.

    This is the permissive bound: the SDK cannot know the caller's tier before
    the request, so anonymous callers may still receive a 413 with a message
    directing them to create a free account.  The server is authoritative.

SECRET_MAX_LENGTH — kept for backwards-compatible display messages.
"""

SECRET_MAX_BYTES: int = 14336
SECRET_MAX_LENGTH: int = 14336
