"""Zephr — secure one-time secret sharing with zero-knowledge encryption."""

__version__ = "0.5.0"

from .client import create_secret, retrieve_secret
from .exceptions import (
    ZephrError,
    EncryptionError,
    ValidationError,
    ApiError,
    NetworkError,
)
from .types import SecretLink, RetrievalResult

__all__ = [
    "create_secret",
    "retrieve_secret",
    "SecretLink",
    "RetrievalResult",
    "ZephrError",
    "EncryptionError",
    "ValidationError",
    "ApiError",
    "NetworkError",
]
