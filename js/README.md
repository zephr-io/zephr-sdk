# zephr

How agents hand off credentials, securely. CLI and JavaScript SDK for [Zephr](https://zephr.io).

Create a one-time secret link: encrypted on your device and self-destructing after a single retrieval. Pass it between agents, services, and pipelines with no shared infrastructure and no plaintext on the server.

Designed for zero-knowledge secret handoff between independent systems: AI agents, CI/CD pipelines, GitHub Actions, and human operators.

**New in Sprint 2:** Webhook callbacks (`--callback-url`) notify your pipeline when a secret is consumed. Idempotency keys are auto-generated on every create for safe retries. See [Webhook callback](#webhook-callback) and [Idempotency](#idempotency) below.

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
- Zero external dependencies: built on Node.js built-ins and Web Crypto only
- Pipe support: reads from stdin for scripting, CI pipelines, and agent environments
- Anonymous use: no account required, rate-limited per IP
- API key support for higher limits and longer expiry
- Webhook callbacks: get notified when a secret is consumed (`callbackUrl` + `callbackSecret`)
- Idempotency: auto-generated `Idempotency-Key` on every create for safe retries

## Installation

```bash
# No installation required — one-off use, CI, agent environments
npx zephr "my-secret"

# Global install
npm install -g zephr

# SDK for Node.js 22+ and browser bundles
npm install zephr
```

## CLI

```bash
zephr <secret> [options]              # Create a one-time secret
echo "secret" | zephr [options]       # Create from stdin
zephr retrieve <link> [options]       # Retrieve and decrypt

Create options:
  -e, --expiry <minutes> Expiration in minutes: 5, 15, 30, 60, 1440, 10080, or 43200 (default: 60; sub-hour values (5, 15, 30) require Dev/Pro; all other values require a free account or higher)
  -s, --split            Return URL and key separately
  -H, --hint <label>     Plaintext label for routing and audit logs (1-128 printable ASCII, not encrypted)
  --callback-url <url>   HTTPS webhook URL — receive a signed event on consumption
  --callback-secret <s>  HMAC-SHA256 signing secret for the webhook (required with --callback-url)
  -k, --api-key <key>    API key; takes precedence over ZEPHR_API_KEY env var

Retrieve options:
      --url <url>        Secret URL (split mode)
      --key <key>        Encryption key (split mode)
  -k, --api-key <key>    API key

General:
  -v, --version          Show version
  -h, --help             Show help
```

### Examples

```bash
# Pass a credential to a downstream process
echo "$DB_PASSWORD" | zephr --expiry 60

# Split mode: URL and key through separate channels
zephr "$API_KEY" --split

# Attach a plaintext label for routing and audit logs
zephr "$API_KEY" --hint STRIPE_KEY_PROD

# From password manager
pass show production/db | zephr

# From file
cat ~/.ssh/id_rsa.pub | zephr

# Authenticated: higher limits and longer expiry
zephr "$API_KEY" --expiry 10080 --api-key zeph_...
ZEPHR_API_KEY=zeph_... zephr "$API_KEY" --expiry 10080

# Dev/Pro: 30-day expiry
zephr "$API_KEY" --expiry 43200 --api-key zeph_...

# Webhook callback — get notified when the secret is consumed
zephr "$API_KEY" --callback-url https://my-server.example.com/zephr-events \
  --callback-secret my-hmac-secret --api-key zeph_...
```

### Idempotency

The CLI auto-generates an `Idempotency-Key` header on every create. If a request times out at the infrastructure level and is replayed, the server returns the cached response without creating a duplicate secret.

### Retrieve

```bash
# Standard mode — pass the full link
zephr retrieve "https://zephr.io/secret/abc123#v1.key..."

# Split mode — URL and key separately
zephr retrieve --url "https://zephr.io/secret/abc123" --key "v1.key..."

# From stdin (e.g. piped from another command)
echo "https://zephr.io/secret/abc123#v1.key..." | zephr retrieve
```

The decrypted secret is written to **stdout** (pipeable). If the secret has a hint, it is written to **stderr**:

```
Hint: STRIPE_KEY_PROD          ← stderr (metadata)
sk-live-abc123                 ← stdout (data)
```

This means `zephr retrieve <link> | pbcopy` copies only the plaintext.

### Output

Standard mode:
```
[OK] Secret encrypted on your device
[OK] Uploaded to Zephr

Link: https://zephr.io/secret/abc123#v1.key...

Expires in 1 hour. One-time access only.
```

Split mode:
```
[OK] Secret encrypted on your device
[OK] Uploaded to Zephr

Split mode - share these separately:

URL: https://zephr.io/secret/abc123
Key: v1.key...

Expires in 1 hour. One-time access only.
```

## Authentication

The CLI and SDK work without an account. No setup required. **Free, Dev, and Pro tier features require an API key.** Pass it via `--api-key` or the `ZEPHR_API_KEY` environment variable. Anonymous requests are capped at 3/day per IP with a 1 h max expiry.

| Tier | Create limit | Expiry options | Max size | Authentication |
|------|-------------|----------------|----------|----------------|
| Anonymous | 3/day | 1h | 6 KB | None |
| Free | 50/month | 1h, 24h, 7d, 30d | 20 KB | `--api-key zeph_...` |
| Dev ($15/mo) | 2,000/month | 5m, 15m, 30m, 1h, 24h, 7d, 30d | 200 KB | `--api-key zeph_...` |
| Pro ($39/mo) | 50,000/month | 5m, 15m, 30m, 1h, 24h, 7d, 30d | 1 MB | `--api-key zeph_...` |

**Getting an API key:** Log in at [zephr.io/account](https://zephr.io/account), open the API Keys tab, and create a key. The raw key is shown exactly once. Copy it immediately.

**Passing the key:**
```bash
# Flag takes precedence over the environment variable
zephr "secret" --api-key zeph_...

# Environment variable: preferred for CI and scripts
export ZEPHR_API_KEY=zeph_...
zephr "secret"

# Inline for one-off use
ZEPHR_API_KEY=zeph_... zephr "secret"
```

**GitHub Actions:** Add `ZEPHR_API_KEY` as a repository secret, then reference it in your workflow. All `zephr` steps are automatically authenticated:

```yaml
env:
  ZEPHR_API_KEY: ${{ secrets.ZEPHR_API_KEY }}

steps:
  - run: echo "$SECRET" | zephr --expiry 60
    env:
      SECRET: ${{ secrets.MY_SECRET }}
```

The key is sent as `Authorization: Bearer zeph_...` on each request. An invalid or revoked key returns HTTP 401.

## JavaScript / TypeScript SDK

Isomorphic: works in Node.js 22+ and any browser bundle. TypeScript declarations included. Zero external dependencies.

```js
import { createSecret, retrieveSecret } from 'zephr';

// Named expiry constants for readability (raw integers also accepted)
import { EXPIRY } from 'zephr/limits.js';
// EXPIRY.MINUTES_5, EXPIRY.MINUTES_15, EXPIRY.MINUTES_30,
// EXPIRY.HOURS_1, EXPIRY.HOURS_24, EXPIRY.DAYS_7, EXPIRY.DAYS_30
```

Agent A encrypts and hands off the link. Agent B retrieves it exactly once:

```js
// Agent A: encrypt and dispatch
const { fullLink } = await createSecret('sk-live-abc123', { expiry: 60 });
agentB.dispatch({ credential: fullLink });

// Agent B: consumed atomically on first read
const { plaintext } = await retrieveSecret(fullLink);
```

Split mode: URL and key through separate channels:

```js
const { url, key } = await createSecret('db-password', { split: true, expiry: 60 });
agentB.dispatch({ credentialUrl: url });
sideChannel.send(key); // key never shares a channel with the URL

const { plaintext } = await retrieveSecret({ url, key });
```

### Return value

`createSecret()` resolves to an object. Standard mode (`split: false`):

```js
{
  mode:      'standard',
  fullLink:  'https://zephr.io/secret/Ht7kR2...#v1.key...',
  expiresAt: '2026-03-08T12:00:00.000Z',  // ISO 8601
  secretId:  'Ht7kR2...',                  // 22-char base64url ID
}
```

Split mode (`split: true`):

```js
{
  mode:      'split',
  url:       'https://zephr.io/secret/Ht7kR2...',
  key:       'v1.key...',
  expiresAt: '2026-03-08T12:00:00.000Z',
  secretId:  'Ht7kR2...',
}
```

`retrieveSecret()` resolves to a `RetrievalResult` object with properties `plaintext` (string), `hint` (string or undefined), and `purgeAt` (string or undefined).

Authenticated use: pass your API key for higher limits and longer expiry:

```js
// Free: 50/mo, 30d max; Dev: 2,000/mo, 30d max; Pro: 50,000/mo, 30d max
const { fullLink } = await createSecret('sk-live-abc123', {
  expiry: 10080,                          // up to 43200 on Dev/Pro
  apiKey: process.env.ZEPHR_API_KEY,      // 'zeph_...'
});

// apiKey is optional on retrieve; include it to count against your authenticated quota
const { plaintext } = await retrieveSecret(fullLink, {
  apiKey: process.env.ZEPHR_API_KEY,
});
```

In GitHub Actions, expose the repository secret as an environment variable and `process.env.ZEPHR_API_KEY` is populated automatically. No code changes needed:

```yaml
env:
  ZEPHR_API_KEY: ${{ secrets.ZEPHR_API_KEY }}
```

### Webhook callback

Get notified when a secret is consumed or expires — no polling needed:

```js
const { fullLink } = await createSecret('db-password', {
  expiry: 60,
  hint: 'DB_PASSWORD_PROD',
  callbackUrl: 'https://my-orchestrator.example.com/zephr-events',
  callbackSecret: 'my-hmac-signing-secret',
  apiKey: process.env.ZEPHR_API_KEY,
});
```

When the secret is retrieved, Zephr POSTs a signed event to your callback URL with an `X-Zephr-Signature` header (HMAC-SHA256 hex digest). Verify the signature against your `callbackSecret`. See [examples/webhook-receiver](https://github.com/zephr-io/zephr-sdk/tree/main/examples/webhook-receiver) for runnable Node.js and Python receivers.

### Idempotency

The SDK auto-generates an `Idempotency-Key` on every create — retries are safe by default. If a request times out and the caller retries, the server returns the cached response without creating a duplicate.

Full SDK reference at [zephr.io/docs](https://zephr.io/docs#js-sdk).

## Error handling

```js
import { createSecret, retrieveSecret, ValidationError, EncryptionError, ApiError, NetworkError } from 'zephr';

try {
  const { fullLink } = await createSecret('my secret');
} catch (err) {
  if (err instanceof ValidationError) {
    // Invalid input: empty or whitespace-only string, exceeds 2,048 bytes, unsupported expiry
  } else if (err instanceof EncryptionError) {
    // AES-GCM key generation or encryption/decryption failed
  } else if (err instanceof ApiError) {
    console.error(err.statusCode);  // e.g. 429, 403, 401, 410
    console.error(err.code);        // e.g. 'MONTHLY_LIMIT_EXCEEDED'
  } else if (err instanceof NetworkError) {
    // Connection failed or timed out
  }
}
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
- No plaintext logging. No analytics in the CLI or SDK.

## Requirements

Node.js 22.0.0 or higher

## License

MIT
