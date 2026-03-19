# zephr

Zero-knowledge one-time secret sharing for AI agents and the humans who orchestrate them. Python SDK for [Zephr](https://zephr.io).

Create a one-time secret link: encrypted on your device and self-destructing after a single retrieval. Pass it between agents, services, and pipelines with no shared infrastructure and no plaintext on the server.

Designed for zero-knowledge secret handoff between independent systems: AI agents, CI/CD pipelines, GitHub Actions, and human operators.

## How it works

1. A 256-bit key is generated locally. It never reaches Zephr's servers.
2. Your secret is encrypted with AES-GCM on your device
3. Only the ciphertext is uploaded to Zephr
4. The link embeds the key in the URL fragment, which browsers never transmit to servers
5. First retrieval atomically consumes the record. A second request returns 410.

## Features

- No shared infrastructure: a link is the entire transport mechanism between independent processes
- Zero-knowledge: the server never receives your plaintext or encryption keys
- Local encryption: AES-GCM-256 on your device before any network call
- One-time access: record marked consumed atomically on first retrieval
- Minimal dependencies: only `cryptography` (audited, widely trusted)
- Anonymous use: no account required, rate-limited per IP
- API key support for higher limits and longer expiry

## Installation

```bash
pip install zephr
```

## Usage

### Create a secret

```python
import zephr

result = zephr.create_secret("my-api-key-12345")
print(result["full_link"])
# https://zephr.io/secret/abc123#v1.key...
```

The secret is encrypted exactly as provided. No trimming or normalization. Strings that are empty or contain only whitespace raise `ValidationError`.

Agent A encrypts and hands off the link. Agent B retrieves it exactly once:

```python
# Agent A: encrypt and dispatch
result = zephr.create_secret("sk-live-abc123", expiry=60, hint="STRIPE_KEY_PROD")
agent_b.dispatch({"credential": result["full_link"]})

# Agent B: consumed atomically on first read
result = zephr.retrieve_secret(result["full_link"])
plaintext = result["plaintext"]
```

### Retrieve a secret

```python
import zephr

# Full URL string
result = zephr.retrieve_secret("https://zephr.io/secret/abc123#v1.key...")
plaintext = result["plaintext"]

# Split mode
result = zephr.retrieve_secret({"url": "https://zephr.io/secret/abc123", "key": "v1.key..."})
plaintext = result["plaintext"]
```

Retrieval is exactly-once. The server permanently destroys the record on first access.

### Options

```python
# Expire in 1 hour
result = zephr.create_secret("secret", expiry=60)

# Expire in 7 days
result = zephr.create_secret("secret", expiry=10080)

# Expire in 30 days (Dev/Pro)
result = zephr.create_secret("secret", expiry=43200, api_key="zeph_...")

# Attach a plaintext label for routing and audit logs
result = zephr.create_secret("secret", hint="STRIPE_KEY_PROD")

# Split URL and key for separate transmission
result = zephr.create_secret("secret", split=True)
print(result["url"])   # https://zephr.io/secret/abc123
print(result["key"])   # v1.key...
```

### Return value

`create_secret()` returns a dict.

Standard mode:
```python
{
    "mode": "standard",
    "full_link": "https://zephr.io/secret/abc123#v1.key...",
    "expires_at": "2026-03-12T12:00:00.000Z",
    "secret_id": "abc123...",               # 22-char base64url ID
}
```

Split mode:
```python
{
    "mode": "split",
    "url": "https://zephr.io/secret/abc123",
    "key": "v1.key...",
    "expires_at": "2026-03-12T12:00:00.000Z",
    "secret_id": "abc123...",               # 22-char base64url ID
}
```

`retrieve_secret()` returns a dict with keys `plaintext` (str), `hint` (str or None), and `purge_at` (str or None).

## Authentication

The SDK works without an account. No setup required. **Free, Dev, and Pro tier features require an API key.** Pass it via the `api_key` parameter. Anonymous requests are capped at 3/day per IP with a 1 h max expiry.

| Tier | Create limit | Expiry options | Max size | Authentication |
|------|-------------|----------------|----------|----------------|
| Anonymous | 3/day | 1h | 6 KB | None |
| Free | 50/month | 1h, 24h, 7d, 30d | 20 KB | `api_key="zeph_..."` |
| Dev ($15/mo) | 2,000/month | 5m, 15m, 30m, 1h, 24h, 7d, 30d | 200 KB | `api_key="zeph_..."` |
| Pro ($39/mo) | 50,000/month | 5m, 15m, 30m, 1h, 24h, 7d, 30d | 1 MB | `api_key="zeph_..."` |

**Getting an API key:** Log in at [zephr.io/account](https://zephr.io/account), open the API Keys tab, and create a key. The raw key is shown exactly once. Copy it immediately.

**Passing the key:**

```python
import os
import zephr

# Via parameter
result = zephr.create_secret("secret", api_key="zeph_...")

# Via environment variable: preferred for CI and scripts
# export ZEPHR_API_KEY=zeph_...
result = zephr.create_secret("secret", api_key=os.environ.get("ZEPHR_API_KEY"))
```

**GitHub Actions:** Add `ZEPHR_API_KEY` as a repository secret, then pass it to your script:

```yaml
steps:
  - run: python share_secret.py
    env:
      ZEPHR_API_KEY: ${{ secrets.ZEPHR_API_KEY }}
```

```python
# share_secret.py
import os, zephr

result = zephr.create_secret(
    os.environ["MY_SECRET"],
    expiry=60,
    api_key=os.environ.get("ZEPHR_API_KEY"),
)
print(result["full_link"])
```

The key is sent as `Authorization: Bearer zeph_...` on each request. An invalid or revoked key returns HTTP 401.

## Error handling

```python
import zephr

try:
    result = zephr.create_secret("my secret")
except zephr.ValidationError:
    # Invalid input: empty or whitespace-only string, too long, bad expiry
    pass
except zephr.ApiError as e:
    # Server returned an error
    print(e.status_code)  # e.g. 429, 401, 403
    print(e.code)         # e.g. "MONTHLY_LIMIT_EXCEEDED"
except zephr.NetworkError:
    # Connection failed or timed out
    pass
```

Common `ApiError` codes:

| Code | Status | Meaning |
|------|--------|---------|
| `INVALID_API_KEY` | 401 | Key not found or revoked |
| `UPGRADE_REQUIRED` | 403 | Feature requires a higher tier (e.g. expiry > 60 min without an account, or sub-hour expiry (5, 15, 30 min) without Dev/Pro) |
| `ANON_RATE_LIMIT_EXCEEDED` | 429 | Anonymous daily limit reached (3/day per IP) |
| `MONTHLY_LIMIT_EXCEEDED` | 429 | Monthly create limit reached for this API key |
| `PAYLOAD_TOO_LARGE` | 413 | Encrypted blob exceeds the tier blob ceiling |
| `SECRET_NOT_FOUND` | 404 | Secret ID does not exist or has expired |
| `SECRET_ALREADY_CONSUMED` | 410 | Secret was already retrieved |
| `SECRET_EXPIRED` | 410 | Secret has passed its expiry time |

## Security

- Encrypts on your device before any network call
- AES-GCM-256 with authenticated encryption and built-in tamper detection
- Keys never reach the server. They travel in the URL fragment ([RFC 3986 §3.5](https://datatracker.ietf.org/doc/html/rfc3986#section-3.5)), which browsers strip before sending requests.
- Sensitive buffers overwritten after use (best-effort in Python)
- No plaintext logging. No analytics in the SDK.

## Requirements

- Python 3.10 or higher
- `cryptography` >= 43.0

## License

MIT
