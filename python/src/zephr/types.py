"""Typed return objects for the Zephr Python SDK.

Frozen dataclasses provide IDE autocompletion, type safety, and immutability.
Callers cannot accidentally mutate return values.

Breaking change in 0.5.0: create_secret() and retrieve_secret() previously
returned plain dicts. Migrate: result["full_link"] -> result.full_link
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecretLink:
    """Result of create_secret().

    Attributes:
        mode: "standard" or "split".
        full_link: Complete shareable URL (standard mode only, None in split mode).
        url: Secret URL without key (split mode only, None in standard mode).
        key: Encryption key string (split mode only, None in standard mode).
        expires_at: ISO 8601 expiration timestamp.
        secret_id: 22-character base64url secret identifier.
    """
    mode: str
    expires_at: str
    secret_id: str
    full_link: str | None = None
    url: str | None = None
    key: str | None = None


@dataclass(frozen=True)
class RetrievalResult:
    """Result of retrieve_secret().

    Attributes:
        plaintext: The decrypted secret string.
        hint: Plaintext label, or None if not set.
        purge_at: Unix timestamp in SECONDS at which the consumed record
            becomes eligible for deletion, or None. Multiply by 1000 for
            millisecond-based APIs; pass to datetime.fromtimestamp() directly.
    """
    plaintext: str
    hint: str | None = None
    purge_at: int | None = None
