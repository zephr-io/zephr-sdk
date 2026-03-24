"""Zephr — secure one-time secret sharing with zero-knowledge encryption."""

__version__ = "0.4.0"

from .client import create_secret, retrieve_secret
from .exceptions import (
    ZephrError,
    EncryptionError,
    ValidationError,
    ApiError,
    NetworkError,
)

__all__ = [
    "create_secret",
    "retrieve_secret",
    "ZephrError",
    "EncryptionError",
    "ValidationError",
    "ApiError",
    "NetworkError",
]
