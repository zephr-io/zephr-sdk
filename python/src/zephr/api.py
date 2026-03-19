"""
API client — handles communication with the Zephr server.
Single responsibility: HTTP transport only.
"""

import json
import re
import socket
import ssl
import urllib.request
import urllib.error
from datetime import datetime
from importlib.metadata import version as _pkg_version

try:
    _SDK_VERSION = _pkg_version("zephr")
except Exception:
    _SDK_VERSION = "0.0.0"

from .exceptions import ApiError, NetworkError, ValidationError

_API_URL = "https://zephr.io/api/secrets"
_TIMEOUT_SECONDS = 10
_MAX_RESPONSE_BYTES = 1_000_000  # 1MB response guard

# 128-bit entropy (16 bytes) encoded as base64url without padding = exactly 22 chars.
# Matches server/middleware/validation.js and server/utils/secureId.js guarantees.
_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{22}$")


def _extract_error_info(body: bytes) -> tuple[str | None, str | None]:
    """Extract (message, code) from an error response body.

    Returns (None, None) when the body cannot be parsed or fields are absent.
    The caller substitutes a generic fallback message.
    """
    try:
        parsed = json.loads(body)
        error = parsed.get("error", {})
        message = (
            error.get("message")
            if isinstance(error, dict)
            else error
            if isinstance(error, str)
            else None
        )
        code = error.get("code") if isinstance(error, dict) else None
        return (
            message if isinstance(message, str) else None,
            code if isinstance(code, str) else None,
        )
    except (json.JSONDecodeError, ValueError, AttributeError, OSError):
        return None, None


def _validate_response(result: dict) -> None:
    """Validate API response structure.

    Defense-in-depth against a malicious or compromised server
    injecting data into URLs. Matches browser and CLI validation.
    """
    if not isinstance(result, dict):
        raise ValidationError("Invalid server response")

    secret_id = result.get("id")
    if not isinstance(secret_id, str) or not _ID_PATTERN.match(secret_id):
        raise ValidationError("Invalid secret ID format from server")

    expires_at = result.get("expires_at")
    if not isinstance(expires_at, str) or not expires_at:
        raise ValidationError("Invalid expiration timestamp from server")
    try:
        datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise ValidationError("Invalid expiration timestamp from server") from exc


def upload_secret(
    encrypted_blob: str,
    expiry: int,
    split_url_mode: bool,
    api_key: str | None = None,
    *,
    hint: str | None = None,
) -> dict:
    """Upload an encrypted secret to the Zephr API.

    Args:
        encrypted_blob: Base64url-encoded encrypted JSON blob.
        expiry: Minutes until expiration. Accepted values: 5, 15, 30, 60, 1440, 10080, or 43200.
            Sub-hour values (5, 15, 30) require a Dev or Pro API key. All other values require a free account or higher.
        split_url_mode: Whether to use split URL mode.
        api_key: Optional Bearer token for authenticated requests.

    Returns:
        Dict with 'id' and 'expires_at' keys.

    Raises:
        ApiError: If the server returns a non-201 status.
        NetworkError: If the request fails or times out.
        ValidationError: If the response structure is invalid.
    """
    body = {
        "encrypted_blob": encrypted_blob,
        "expiry": expiry,
        "split_url_mode": split_url_mode,
    }
    if hint:
        body["hint"] = hint
    payload = json.dumps(body).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(payload)),
        "User-Agent": f"zephr-python/{_SDK_VERSION}",
    }
    if api_key is not None:
        headers["Authorization"] = f"Bearer {api_key}"

    # HTTPS-only — no option to downgrade
    context = ssl.create_default_context()

    req = urllib.request.Request(
        _API_URL,
        data=payload,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            req, timeout=_TIMEOUT_SECONDS, context=context
        ) as resp:
            data = resp.read(_MAX_RESPONSE_BYTES)

            if resp.status != 201:
                raise ApiError(
                    f"Request failed (HTTP {resp.status})",
                    status_code=resp.status,
                )

            result = json.loads(data)
            _validate_response(result)
            return {"id": result["id"], "expires_at": result["expires_at"]}

    except urllib.error.HTTPError as exc:
        status = exc.code
        message, code = _extract_error_info(exc.read(_MAX_RESPONSE_BYTES))
        raise ApiError(
            message or f"Request failed (HTTP {status})",
            status_code=status,
            code=code,
        ) from exc

    except urllib.error.URLError as exc:
        raise NetworkError(f"Network error: {exc.reason}") from exc

    except (TimeoutError, socket.timeout) as exc:
        raise NetworkError("Request timed out (10s)") from exc

    except json.JSONDecodeError as exc:
        raise ApiError("Invalid JSON response from server") from exc


def fetch_secret(
    secret_id: str,
    api_key: str | None = None,
) -> dict:
    """Fetch and consume an encrypted secret from the Zephr API.

    This operation is exactly-once: the server permanently destroys the record
    on first access. A second request for the same ID returns 410 Gone.

    Args:
        secret_id: 22-character base64url secret identifier.
        api_key: Optional Bearer token for authenticated requests.

    Returns:
        Dict with ``encrypted_blob`` (str), ``purge_at`` (str or None),
        and ``hint`` (str or None).

    Raises:
        ApiError: 404 (not found), 410 (consumed or expired), 429 (rate limited).
        NetworkError: If the request fails or times out.
        ValidationError: If the secret ID or response is malformed.
    """
    # Validate before interpolating into URL — defense-in-depth against
    # path traversal if called outside the public API.
    if not _ID_PATTERN.match(secret_id):
        raise ValidationError("Invalid secret ID format.")

    headers = {"User-Agent": f"zephr-python/{_SDK_VERSION}"}
    if api_key is not None:
        headers["Authorization"] = f"Bearer {api_key}"

    context = ssl.create_default_context()

    req = urllib.request.Request(
        f"{_API_URL}/{secret_id}",
        headers=headers,
        method="GET",
    )

    try:
        with urllib.request.urlopen(
            req, timeout=_TIMEOUT_SECONDS, context=context
        ) as resp:
            data = resp.read(_MAX_RESPONSE_BYTES)

            if resp.status != 200:
                message, code = _extract_error_info(data)
                raise ApiError(
                    message or f"Request failed (HTTP {resp.status})",
                    status_code=resp.status,
                    code=code,
                )

            result = json.loads(data)

            if not isinstance(result, dict):
                raise ValidationError("Invalid server response: expected a JSON object.")

            encrypted_blob = result.get("encrypted_blob")
            if not isinstance(encrypted_blob, str) or not re.match(
                r"^[A-Za-z0-9_-]+$", encrypted_blob
            ):
                raise ValidationError(
                    "Invalid server response: malformed encrypted blob."
                )

            purge_at = result.get("purge_at")

            return {
                "encrypted_blob": encrypted_blob,
                "purge_at": str(purge_at) if purge_at is not None else None,
                "hint": result.get("hint"),
            }

    except urllib.error.HTTPError as exc:
        status = exc.code
        message, code = _extract_error_info(exc.read(_MAX_RESPONSE_BYTES))
        raise ApiError(
            message or f"Request failed (HTTP {status})",
            status_code=status,
            code=code,
        ) from exc

    except urllib.error.URLError as exc:
        raise NetworkError(f"Network error: {exc.reason}") from exc

    except (TimeoutError, socket.timeout) as exc:
        raise NetworkError("Request timed out (10s)") from exc

    except json.JSONDecodeError as exc:
        raise ApiError("Invalid JSON response from server") from exc
