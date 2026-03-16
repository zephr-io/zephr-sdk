"""Domain-specific exceptions for the Zephr SDK."""


class ZephrError(Exception):
    """Base exception for all Zephr SDK errors."""


class EncryptionError(ZephrError):
    """Raised when encryption or key generation fails."""


class ValidationError(ZephrError):
    """Raised when input validation fails."""


class ApiError(ZephrError):
    """Raised when the Zephr API returns an error.

    Attributes:
        status_code: HTTP status code, or None if unavailable.
        code: Machine-readable error code from the server response body
              (e.g. ``'RATE_LIMIT_EXCEEDED'``, ``'SECRET_ALREADY_CONSUMED'``),
              or None when the server did not return a structured error envelope.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


class NetworkError(ZephrError):
    """Raised when a network request fails."""
