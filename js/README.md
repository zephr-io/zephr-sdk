# zephr

How agents hand off credentials, securely. CLI and JavaScript SDK for [Zephr](https://zephr.io).

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
- Zero external dependencies: built on Node.js built-ins and Web Crypto only
- Pipe support: reads from stdin for scripting, CI pipelines, and agent environments
- Anonymous use: no account required, rate-limited per IP
- API key support for higher limits and longer expiry

## Installation

```bash
# No installation required — one-off use, CI, agent environments
npx zephr "my-secret"

# Global install
npm install -g zephr

# SDK for Node.js 20+ and browser bundles
npm install zephr
```

## CLI

```bash
zephr <secret> [options]
echo "secret" | zephr [options]

Options:
  -e, --expiry <hours>   Expiration: 1, 24, 168, or 720 (default: 1; 24h+ requires a free account; 720 requires Dev/Pro)
  -s, --split            Return URL and key separately
  -k, --api-key <key>    API key; takes precedence over ZEPHR_API_KEY env var
  -v, --version          Show version
  -h, --help             Show help
```

### Examples

```bash
# Pass a credential to a downstream process
echo "$DB_PASSWORD" | zephr --expiry 1

# Split mode: URL and key through separate channels
zephr "$API_KEY" --split

# From password manager
pass show production/db | zephr

# From file
cat ~/.ssh/id_rsa.pub | zephr

# Authenticated: higher limits and longer expiry
zephr "$API_KEY" --expiry 168 --api-key zeph_...
ZEPHR_API_KEY=zeph_... zephr "$API_KEY" --expiry 168

# Dev/Pro: 30-day expiry
zephr "$API_KEY" --expiry 720 --api-key zeph_...
```

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

| Tier | Create limit | Max expiry | Max size | Authentication |
|------|-------------|------------|----------|----------------|
| Anonymous | 3/day | 1 h | 6 KB | None |
| Free | 50/month | 7 days | 20 KB | `--api-key zeph_...` |
| Dev ($15/mo) | 2,000/month | 30 days | 200 KB | `--api-key zeph_...` |
| Pro ($39/mo) | 50,000/month | 30 days | 1 MB | `--api-key zeph_...` |

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
  - run: echo "$SECRET" | zephr --expiry 1
    env:
      SECRET: ${{ secrets.MY_SECRET }}
```

The key is sent as `Authorization: Bearer zeph_...` on each request. An invalid or revoked key returns HTTP 401.

## JavaScript / TypeScript SDK

Isomorphic: works in Node.js 20+ and any browser bundle. TypeScript declarations included. Zero external dependencies.

```js
import { createSecret, retrieveSecret } from 'zephr';
```

Agent A encrypts and hands off the link. Agent B retrieves it exactly once:

```js
// Agent A: encrypt and dispatch
const { fullLink } = await createSecret('sk-live-abc123', { expiry: 1 });
agentB.dispatch({ credential: fullLink });

// Agent B: consumed atomically on first read
const secret = await retrieveSecret(fullLink);
```

Split mode: URL and key through separate channels:

```js
const { url, key } = await createSecret('db-password', { split: true, expiry: 1 });
agentB.dispatch({ credentialUrl: url });
sideChannel.send(key); // key never shares a channel with the URL

const secret = await retrieveSecret({ url, key });
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

`retrieveSecret()` resolves to the decrypted plaintext string.

Authenticated use: pass your API key for higher limits and longer expiry:

```js
// Free: 50/mo, 7d max; Dev: 2,000/mo, 30d max; Pro: 50,000/mo, 30d max
const { fullLink } = await createSecret('sk-live-abc123', {
  expiry: 168,                            // up to 720 on Dev/Pro
  apiKey: process.env.ZEPHR_API_KEY,      // 'zeph_...'
});

// apiKey is optional on retrieve; include it to count against your authenticated quota
const secret = await retrieveSecret(fullLink, {
  apiKey: process.env.ZEPHR_API_KEY,
});
```

In GitHub Actions, expose the repository secret as an environment variable and `process.env.ZEPHR_API_KEY` is populated automatically. No code changes needed:

```yaml
env:
  ZEPHR_API_KEY: ${{ secrets.ZEPHR_API_KEY }}
```

Full SDK reference at [zephr.io/docs](https://zephr.io/docs#js-sdk).

## Error handling

```js
import { createSecret, retrieveSecret, ValidationError, ApiError, NetworkError } from 'zephr';

try {
  const { fullLink } = await createSecret('my secret');
} catch (err) {
  if (err instanceof ValidationError) {
    // Invalid input: empty or whitespace-only string, exceeds 2,048 bytes, unsupported expiry
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
| `UPGRADE_REQUIRED` | 403 | Feature requires a higher tier (e.g. expiry > 1h without an account, or 720h without Dev/Pro) |
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

Node.js 20.0.0 or higher

## License

MIT
