"""
Encryption module — AES-GCM-256 operations.
Single responsibility: cryptographic operations only.

Produces output compatible with the Zephr web app and CLI:
- Key format: v1.<base64url-encoded-32-bytes>
- Blob format: base64url(JSON.stringify({iv: base64url, ciphertext: base64url}))

All encoding layers use base64url (RFC 4648 §5): URL-safe alphabet, no padding.
"""

import base64
import json
import os
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import EncryptionError
from .memory import zero_bytes

# AES-GCM-256 constants
_KEY_BYTES = 32  # 256 bits
_IV_BYTES = 12  # 96 bits per NIST SP 800-38D
_KEY_VERSION = "v1"

# base64url(32 bytes) without padding: ceil(32 * 4 / 3) = 43 characters
_KEY_STRING_LENGTH = 43

# Supported key versions — checked on decrypt; extend this set for future versions.
_SUPPORTED_KEY_VERSIONS = frozenset({"v1"})

# Matches "v<1-3 digit version>.<base64url payload>"
_KEY_RE = re.compile(r"^v(\d{1,3})\.([A-Za-z0-9_-]+)$")


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url (RFC 4648) without padding.

    Matches browser Base64Utils.arrayToBase64Url and
    Node.js Buffer.toString('base64url').
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    """Decode a base64url string (RFC 4648) without padding.

    Re-adds the required padding before decoding.
    """
    missing = (-len(data)) % 4
    if missing:
        data += "=" * missing
    return base64.urlsafe_b64decode(data)


def generate_key() -> tuple[bytes, str]:
    """Generate a 256-bit AES-GCM key and its versioned string representation.

    Returns:
        Tuple of (raw_key_bytes, key_string) where key_string is "v1.<base64url>".
    """
    raw = bytearray(os.urandom(_KEY_BYTES))
    try:
        key_string = f"{_KEY_VERSION}.{_base64url_encode(bytes(raw))}"
        key_bytes = bytes(raw)
        return key_bytes, key_string
    finally:
        zero_bytes(raw)


def encrypt(plaintext_bytes: bytes, key: bytes) -> str:
    """Encrypt raw bytes using AES-GCM-256.

    The caller is responsible for encoding (str -> bytes) before calling.
    This function encrypts exactly the bytes it receives — no mutation,
    no normalization, no encoding assumptions.

    Args:
        plaintext_bytes: Raw bytes to encrypt.
        key: 32-byte AES key.

    Returns:
        Base64url-encoded JSON string matching the Zephr blob format:
        base64url(JSON.stringify({iv: base64url, ciphertext: base64url}))

    Raises:
        EncryptionError: If encryption fails.
        TypeError: If plaintext_bytes is not bytes.
    """
    if not isinstance(plaintext_bytes, bytes):
        raise TypeError(
            "encrypt() requires bytes — encoding must happen at the call site"
        )

    if not isinstance(key, bytes) or len(key) != _KEY_BYTES:
        raise EncryptionError(f"Invalid key: must be exactly {_KEY_BYTES} bytes.")

    try:
        iv = os.urandom(_IV_BYTES)
        aesgcm = AESGCM(key)

        # AES-GCM appends the 16-byte auth tag to the ciphertext
        ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)

        # Match browser/CLI format: {iv: base64url, ciphertext: base64url}
        encrypted_data = {
            "iv": _base64url_encode(iv),
            "ciphertext": _base64url_encode(ciphertext),
        }

        # Outer wrapper: base64url without padding (matches browser
        # Base64Utils.arrayToBase64Url and Node.js Buffer.toString('base64url')).
        json_bytes = json.dumps(encrypted_data, separators=(",", ":"), ensure_ascii=False).encode("ascii")
        return base64.urlsafe_b64encode(json_bytes).rstrip(b"=").decode("ascii")

    except Exception as exc:
        raise EncryptionError(f"Encryption failed: {exc}") from exc


def decrypt(encrypted_blob: str, key_string: str) -> bytes:
    """Decrypt an AES-GCM-256 encrypted blob produced by Zephr.

    Matches the wire format produced by encrypt() and the Zephr web/CLI clients:
    ``base64url(JSON.stringify({iv: base64url, ciphertext: base64url}))``.

    Args:
        encrypted_blob: Base64url-encoded JSON blob in Zephr format.
        key_string: Versioned key string (e.g., ``"v1.<base64url>"``).

    Returns:
        Decrypted plaintext as raw bytes. The caller is responsible for decoding
        (e.g., ``.decode("utf-8")``) if a string is needed.

    Raises:
        EncryptionError: If the key format is invalid, the blob is malformed,
                         or AES-GCM authentication / decryption fails.
    """
    # --- Parse and validate key string ---
    match = _KEY_RE.match(key_string)
    if not match:
        raise EncryptionError("Invalid key string format.")

    version = f"v{match.group(1)}"
    if version not in _SUPPORTED_KEY_VERSIONS:
        raise EncryptionError(
            f"Unsupported key version: {version}. "
            f"Supported: {', '.join(sorted(_SUPPORTED_KEY_VERSIONS))}."
        )

    key_payload = match.group(2)
    if len(key_payload) != _KEY_STRING_LENGTH:
        raise EncryptionError(
            f"Invalid key payload length: expected {_KEY_STRING_LENGTH} characters, "
            f"got {len(key_payload)}."
        )

    key_bytes_raw = bytearray()
    try:
        try:
            key_bytes_raw = bytearray(_base64url_decode(key_payload))
        except ValueError as exc:
            raise EncryptionError("Invalid key encoding.") from exc

        if len(key_bytes_raw) != _KEY_BYTES:
            raise EncryptionError(
                f"Invalid key length: expected {_KEY_BYTES} bytes, "
                f"got {len(key_bytes_raw)}."
            )

        # --- Decode the outer base64url wrapper ---
        try:
            json_bytes = _base64url_decode(encrypted_blob)
            blob_data = json.loads(json_bytes)
        except (ValueError, json.JSONDecodeError) as exc:
            raise EncryptionError("Invalid encrypted blob format.") from exc

        if (
            not isinstance(blob_data, dict)
            or "iv" not in blob_data
            or "ciphertext" not in blob_data
        ):
            raise EncryptionError("Encrypted blob is missing required fields.")

        try:
            iv = _base64url_decode(blob_data["iv"])
            ciphertext = _base64url_decode(blob_data["ciphertext"])
        except (ValueError, KeyError) as exc:
            raise EncryptionError("Invalid IV or ciphertext encoding.") from exc

        # --- AES-GCM decrypt (auth tag is appended to ciphertext by AESGCM) ---
        try:
            aesgcm = AESGCM(bytes(key_bytes_raw))
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
        except Exception as exc:
            raise EncryptionError(f"Decryption failed: {exc}") from exc

        return plaintext

    finally:
        zero_bytes(key_bytes_raw)
