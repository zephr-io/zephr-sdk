"""
Link generator — creates shareable URLs.
Single responsibility: URL construction only.
"""

_BASE_URL = "https://zephr.io"


def generate_link(
    secret_id: str,
    key_string: str,
    split: bool = False,
) -> dict:
    """Generate a shareable link for a secret.

    Args:
        secret_id: Secret identifier from the API.
        key_string: Versioned key string (e.g., "v1.<base64url>").
        split: Whether to return URL and key separately.

    Returns:
        Dict with 'mode' and either 'full_link' or 'url'+'key'.
    """
    if split:
        return {
            "mode": "split",
            "url": f"{_BASE_URL}/secret/{secret_id}",
            "key": key_string,
        }

    return {
        "mode": "standard",
        "full_link": f"{_BASE_URL}/secret/{secret_id}#{key_string}",
    }
