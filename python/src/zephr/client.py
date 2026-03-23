"""
Zephr client — orchestrates encryption, upload, and link generation.
Single responsibility: workflow coordination via composition.

Modules are composed, not inherited. Each module handles one concern:
- crypto: encryption and key generation
- api: HTTP transport
- link: URL construction

This module wires them together into a single create_secret() or
retrieve_secret() call.
"""

import re
import urllib.parse

from .crypto import decrypt, encrypt, generate_key
from .memory import zero_bytes
from .api import fetch_secret, upload_secret
from .link import generate_link
from .limits import SECRET_MAX_BYTES
from .exceptions import EncryptionError, ValidationError

# Valid expiry options (minutes) — matches web app and CLI
_VALID_EXPIRY_MINUTES = frozenset({5, 15, 30, 60, 1440, 10080, 43200})

_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost")
_BLOCKED_HOSTS = frozenset({"localhost", "metadata.google.internal"})


def _is_private_host(hostname: str) -> bool:
    """Client-side private host precheck — no DNS resolution.

    The server performs the authoritative DNS-level check at dispatch time.
    """
    lower = hostname.lower()
    if lower in _BLOCKED_HOSTS:
        return True
    if any(lower.endswith(s) for s in _BLOCKED_SUFFIXES):
        return True
    # Integer or hex IP representations.
    if re.fullmatch(r"\d+", lower) or re.fullmatch(r"0x[0-9a-f]+", lower, re.IGNORECASE):
        return True
    # IPv4 private/reserved ranges.
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", lower)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if a in (0, 10, 127):
            return True
        if a == 100 and 64 <= b <= 127:       # 100.64/10 CGNAT
            return True
        if a == 169 and b == 254:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 0:               # 192.0.0/24
            return True
        if a == 192 and b == 168:
            return True
        if a == 198 and b in (18, 19):        # 198.18/15
            return True
        if a >= 224:                          # 224/4 + 240/4
            return True
    # IPv6 private/reserved ranges.
    bare = lower.strip("[]")
    if bare in ("::1", "::"):                 # loopback + unspecified
        return True
    if re.match(r"^fe[89abcdef]", bare):       # fe80::/10 link-local + fec0::/10 site-local
        return True
    if bare.startswith("fc") or bare.startswith("fd"):  # fc00::/7
        return True
    if bare.startswith("ff"):                 # ff00::/8 multicast
        return True
    mapped = re.fullmatch(r"::ffff:(\d+\.\d+\.\d+\.\d+)", bare)
    if mapped:
        return _is_private_host(mapped.group(1))
    return False

# Matches the secret ID segment in a URL path: /secret/<22-char base64url>
_SECRET_ID_RE = re.compile(r"^/secret/([A-Za-z0-9_-]{22})(?:[/?#]|$)")


def create_secret(
    secret: str,
    *,
    expiry: int = 60,
    split: bool = False,
    hint: str | None = None,
    api_key: str | None = None,
    callback_url: str | None = None,
    callback_secret: str | None = None,
    idempotency_key: str | None = None,
) -> dict:
    """Create an encrypted one-time secret on Zephr.

    This is the primary SDK entry point. It validates input, encrypts
    on your device, uploads the encrypted blob, and returns a shareable link.

    The exact secret string is encrypted unchanged — no trimming or
    normalization is applied. Empty strings and strings consisting entirely of
    whitespace are rejected. The caller is responsible for any other pre-processing.

    Args:
        secret: The plaintext secret to share (max 2,048 UTF-8 bytes).
        expiry: Minutes until expiration — 5, 15, 30, 60, 1440, 10080, or 43200
            (default: 60). Sub-hour values (5, 15, 30) require a Dev or Pro API key.
            All other values require a free account or higher.
        split: If True, return URL and key separately for split sharing.
        hint: Optional plaintext label for routing and audit logs. Not encrypted.
            Must be 1-128 printable ASCII characters.
        api_key: Optional API key for authenticated requests.

    Returns:
        Dict containing:
            - mode: "standard" or "split"
            - full_link: Complete shareable URL (standard mode only)
            - url: Secret URL without key (split mode only)
            - key: Encryption key string (split mode only)
            - expires_at: ISO 8601 expiration timestamp
            - secret_id: 22-character base64url secret identifier

    Raises:
        ValidationError: If input is invalid (empty or whitespace-only secret, exceeds 2,048 UTF-8 bytes,
            invalid expiry value).
        EncryptionError: If encryption fails.
        ApiError: If the server returns an error. Common cases:
            - 413 PAYLOAD_TOO_LARGE: encrypted blob exceeds the per-tier ceiling
              (anonymous: 6KB, free: 20KB, dev: 200KB, pro: 1MB). Reduce the secret
              size or authenticate with a higher-tier API key.
            - 429 ANON_RATE_LIMIT_EXCEEDED / MONTHLY_LIMIT_EXCEEDED: creation rate or
              monthly quota reached. See err.code for details.
            - 403 UPGRADE_REQUIRED: the requested expiry requires a higher tier.
        NetworkError: If the request fails.

    Example::

        import zephr

        result = zephr.create_secret("my-api-key", expiry=60)
        print(result["full_link"])

        result = zephr.create_secret("password", split=True)
        print(result["url"])
        print(result["key"])
    """
    # --- Validate input ---
    if not isinstance(secret, str):
        raise ValidationError("Secret must be a string")

    if not secret.strip():
        raise ValidationError("Secret cannot be empty or whitespace only")

    byte_length = len(secret.encode("utf-8"))
    if byte_length > SECRET_MAX_BYTES:
        raise ValidationError(
            f"Secret too long ({byte_length:,} UTF-8 bytes; max {SECRET_MAX_BYTES:,})"
        )

    if isinstance(expiry, bool) or not isinstance(expiry, int) or expiry not in _VALID_EXPIRY_MINUTES:
        raise ValidationError("expiry must be 5, 15, 30, 60, 1440, 10080, or 43200 (minutes)")

    if api_key is None and expiry != 60:
        raise ValidationError(
            "Anonymous use is limited to 60-minute expiry — pass api_key= to unlock other expiry values "
            "(free: up to 30 days, Dev/Pro: adds sub-hour). Create a free account at https://zephr.io/account"
        )

    if not isinstance(split, bool):
        raise ValidationError("split must be a boolean")

    if hint is not None:
        if not isinstance(hint, str):
            raise ValidationError("hint must be a string")
        if len(hint) < 1 or len(hint) > 128:
            raise ValidationError("hint must be 1-128 characters")
        if not re.fullmatch(r"[\x20-\x7E]+", hint):
            raise ValidationError("hint must contain only printable ASCII characters")

    # --- Callback validation ---
    if callback_url is not None:
        if not isinstance(callback_url, str):
            raise ValidationError("callback_url must be a string")
        if len(callback_url) > 2048:
            raise ValidationError("callback_url must not exceed 2,048 characters")
        parsed_cb = urllib.parse.urlparse(callback_url)
        if parsed_cb.scheme != "https":
            raise ValidationError("callback_url must use HTTPS")
        if _is_private_host(parsed_cb.hostname or ""):
            raise ValidationError("callback_url must not point to a private or reserved address")
        if callback_secret is None:
            raise ValidationError("callback_secret is required when callback_url is provided")

    if callback_secret is not None:
        if callback_url is None:
            raise ValidationError("callback_secret requires callback_url")
        if not isinstance(callback_secret, str):
            raise ValidationError("callback_secret must be a string")
        if len(callback_secret) < 1 or len(callback_secret) > 256:
            raise ValidationError("callback_secret must be 1-256 characters")

    if idempotency_key is not None:
        if not isinstance(idempotency_key, str):
            raise ValidationError("idempotency_key must be a string")
        if len(idempotency_key) < 1 or len(idempotency_key) > 64:
            raise ValidationError("idempotency_key must be 1-64 characters")
        if not re.fullmatch(r"[A-Za-z0-9-]+", idempotency_key):
            raise ValidationError("idempotency_key must contain only alphanumeric characters and hyphens")

    # --- Encoding boundary: str -> UTF-8 bytes ---
    secret_bytes = bytearray(secret.encode("utf-8"))
    key_bytes = None

    try:
        # Generate key
        raw_key, key_string = generate_key()
        key_bytes = bytearray(raw_key)

        # Encrypt (operates on raw bytes — no encoding assumptions)
        encrypted_blob = encrypt(bytes(secret_bytes), bytes(key_bytes))

        # Upload
        result = upload_secret(
            encrypted_blob, expiry, split, api_key,
            hint=hint, callback_url=callback_url, callback_secret=callback_secret,
            idempotency_key=idempotency_key,
        )

        # Generate link
        link_data = generate_link(result["id"], key_string, split)
        link_data["expires_at"] = result["expires_at"]
        link_data["secret_id"] = result["id"]

        return link_data

    finally:
        # 3-pass memory overwrite — best effort in Python
        zero_bytes(secret_bytes)
        if key_bytes is not None:
            zero_bytes(key_bytes)


def _parse_retrieve_input(link) -> tuple[str, str]:
    """Parse a secret link into (secret_id, key_string).

    Accepts:
        - Full URL string: ``"https://zephr.io/secret/<id>#v1.<key>"``
        - Split dict: ``{"url": "https://zephr.io/secret/<id>", "key": "v1.<key>"}``

    Returns:
        Tuple of (secret_id, key_string).

    Raises:
        ValidationError: If the input cannot be parsed.
    """
    if isinstance(link, str):
        parsed = urllib.parse.urlparse(link)
        if not parsed.fragment:
            raise ValidationError(
                "link must include an encryption key in the URL fragment (after #)."
            )
        pathname = parsed.path
        key_string = parsed.fragment

    elif isinstance(link, dict):
        url = link.get("url")
        key_string = link.get("key")
        if not isinstance(url, str):
            raise ValidationError("link['url'] must be a string.")
        if not isinstance(key_string, str):
            raise ValidationError("link['key'] must be a string.")
        parsed = urllib.parse.urlparse(url)
        pathname = parsed.path

    else:
        raise ValidationError(
            "retrieve_secret expects a full URL string or a "
            "{'url': ..., 'key': ...} dict."
        )

    # Match against the path component only — immune to query params and fragments
    id_match = _SECRET_ID_RE.search(pathname)
    if not id_match:
        raise ValidationError(
            "Cannot parse a valid secret ID from the URL. "
            "Expected format: /secret/<22-character ID>."
        )

    if not key_string:
        raise ValidationError("Encryption key is missing.")

    return id_match.group(1), key_string


def retrieve_secret(
    link,
    *,
    api_key: str | None = None,
) -> dict:
    """Retrieve and decrypt a one-time secret from Zephr.

    This operation is exactly-once: the server permanently destroys the record
    on first access. A second request for the same secret returns a 410 error
    regardless of timing.

    Args:
        link: Full URL string (``"https://zephr.io/secret/<id>#v1.<key>"``) or
              a split dict (``{"url": "https://zephr.io/secret/<id>", "key": "v1.<key>"}``).
        api_key: Optional API key for authenticated requests.

    Returns:
        Dict with ``plaintext`` (str), ``hint`` (str or None), and
        ``purge_at`` (str or None).

    Raises:
        ValidationError: If the link format is invalid.
        ApiError: If the server returns an error (404, 410, 429, etc.).
        NetworkError: If the request fails.
        EncryptionError: If decryption fails.

    Example::

        import zephr

        result = zephr.retrieve_secret(
            "https://zephr.io/secret/abc123...#v1.key..."
        )
        print(result["plaintext"])  # decrypted secret
        print(result["hint"])       # plaintext label, or None

        # Split mode
        result = zephr.retrieve_secret(
            {"url": "https://zephr.io/secret/abc123...", "key": "v1.key..."}
        )
        print(result["plaintext"])
    """
    secret_id, key_string = _parse_retrieve_input(link)

    response = fetch_secret(secret_id, api_key=api_key)

    plaintext_bytes = bytearray(decrypt(response["encrypted_blob"], key_string))
    try:
        try:
            plaintext = plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EncryptionError("Decrypted content is not valid UTF-8.") from exc
        return {
            "plaintext": plaintext,
            "hint": response.get("hint"),
            "purge_at": response.get("purge_at"),
        }
    finally:
        zero_bytes(plaintext_bytes)
