"""
Shared input limits for the Zephr Python SDK.
Single source of truth — update here to change across the entire SDK.
Must stay in sync with public/limits.js (web) and cli/limits.js (CLI).

SECRET_MAX_BYTES — SDK / programmatic limit.
    Enforced on the UTF-8 encoded byte length of the plaintext.
    2,048 bytes produces a ~2.8 KB encrypted blob — well within the 16 KB
    server limit.  For pure-ASCII secrets this is equivalent to 2,048 chars;
    for multi-byte Unicode the effective character count is lower.

SECRET_MAX_LENGTH — kept for backwards-compatible display messages.
"""

SECRET_MAX_BYTES: int = 2048
SECRET_MAX_LENGTH: int = 2048
