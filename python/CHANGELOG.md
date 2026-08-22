# Changelog

All notable changes to the `zephr` Python SDK.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is below 1.0.0, breaking changes may land in a minor release.

Releases before 0.5.0 predate this file; see the `pypi-v*` git tags for that history.

## [0.5.0] - 2026-08-16

### Breaking

- `RetrievalResult.purge_at` is now an **`int`** — a Unix timestamp in seconds —
  instead of a `str`.

  It was documented as an ISO 8601 timestamp but returned the numeric wire
  value passed through `str()`, so it arrived as `"1771957320"` and
  `datetime.fromisoformat()` on it always raised. The type now matches what the
  API actually returns.

  ```python
  # before (never worked as documented)
  datetime.fromisoformat(result.purge_at)

  # after
  datetime.fromtimestamp(result.purge_at, tz=timezone.utc)
  ```

### Added

- Anonymous callers may now use 5, 15 and 30 minute expiries, not only 60.

### Changed

- `SECRET_MAX_BYTES` raised from 2,048 to 14,336 UTF-8 bytes (7×), derived from
  the 20KB encrypted-blob ceiling the free tier allows.
- Account tiers simplified to anonymous and free; the free monthly quota is now
  500 creates.

### Fixed

- `retrieve_secret()` now validates the encryption key **before** the one-time
  fetch. Retrieval consumes the record, so a truncated or mangled key
  previously destroyed the secret and then failed to decrypt it — losing it
  permanently. A malformed key now raises `EncryptionError` offline, with the
  secret still retrievable using a corrected link.
- `create_secret()` no longer rejects sub-hour expiries for anonymous callers.
  The client carried a local copy of a server rule (`expiry != 60`) that went
  stale when the anonymous allowance widened, so requests the server accepts
  raised `ValidationError` before being sent. Which expiry values a tier may
  use is now decided solely by the server, which returns `403 UPGRADE_REQUIRED`
  listing the permitted values.
