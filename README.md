# zephr

How agents hand off credentials, securely. CLI, JavaScript SDK, and Python SDK for [Zephr](https://zephr.io).

Create a one-time secret link: encrypted on your device and self-destructing after a single retrieval. Pass it between agents, services, and pipelines with no shared infrastructure and no plaintext on the server.

Built for zero-knowledge secret handoff between independent systems: AI agents, CI/CD pipelines, GitHub Actions, and human operators.

- [npm package](https://www.npmjs.com/package/zephr): JavaScript SDK + CLI (Node.js 20+)
- [PyPI package](https://pypi.org/project/zephr): Python SDK (Python 3.10+)
- [API docs](https://zephr.io/docs)
- [zephr.io](https://zephr.io)

---

## How it works

1. A 256-bit key is generated locally. It never reaches Zephr's servers.
2. Your secret is encrypted with AES-GCM on your device
3. Only the ciphertext is uploaded to Zephr
4. The link embeds the key in the URL fragment, which browsers never transmit to servers
5. First retrieval atomically consumes the record. A second request returns 410.

---

## Features

- No shared infrastructure: a link is the entire transport mechanism between independent processes
- Zero-knowledge: the server never receives your plaintext or encryption keys
- Local encryption: AES-GCM-256 on your device before any network call
- One-time access: the record is permanently deleted after a single retrieval
- Anonymous use: no account required, rate-limited per IP
- API key support for higher limits and longer expiry

---

## CLI and JavaScript SDK

### Install

```bash
# For one-off use, CI scripts, and agent environments
npx zephr "my-secret"

# Global install
npm install -g zephr

# SDK for Node.js 20+ and browser bundles
npm install zephr
```

### Create a secret

```js
import { createSecret } from 'zephr';

// Agent A: encrypt and dispatch
const { fullLink } = await createSecret('sk-live-abc123', { expiry: 1 });
agentB.dispatch({ credential: fullLink });
```

### Retrieve a secret

```js
import { retrieveSecret } from 'zephr';

// Agent B: retrieve once, then permanently deleted
const secret = await retrieveSecret(fullLink);
```

### Split mode: URL and key through separate channels

```js
const { url, key } = await createSecret('db-password', { split: true, expiry: 1 });
agentB.dispatch({ credentialUrl: url });
sideChannel.send(key); // key never shares a channel with the URL

const secret = await retrieveSecret({ url, key });
```

### CLI

```bash
# Pass a credential to a downstream process
echo "$DB_PASSWORD" | zephr --expiry 1

# Split mode: URL and key through separate channels
zephr "$API_KEY" --split

# Authenticated: higher limits and longer expiry
zephr "$API_KEY" --expiry 168 --api-key zeph_...
```

Full CLI and JavaScript SDK reference: [zephr.io/docs](https://zephr.io/docs)

---

## Python SDK

### Install

```bash
pip install zephr
```

### Create a secret

```python
import zephr

# Agent A: encrypt and dispatch
result = zephr.create_secret("sk-live-abc123", expiry_hours=1)
agent_b.dispatch({"credential": result["full_link"]})
```

### Retrieve a secret

```python
# Agent B: retrieve once, then permanently deleted
secret = zephr.retrieve_secret(result["full_link"])
```

### Split mode: URL and key through separate channels

```python
result = zephr.create_secret("db-password", split=True, expiry_hours=1)
agent_b.dispatch({"credential_url": result["url"]})
side_channel.send(result["key"])  # key never shares a channel with the URL

secret = zephr.retrieve_secret({"url": result["url"], "key": result["key"]})
```

Full Python SDK reference: [zephr.io/docs](https://zephr.io/docs)

---

## Authentication

The CLI and both SDKs work without an account. No setup required. **Free, Dev, and Pro tier features require an API key.** Anonymous requests are capped at 3/day per IP with a 1 h max expiry.

| Tier | Create limit | Max expiry | Max size |
|------|-------------|------------|----------|
| Anonymous | 3/day | 1 h | 6 KB |
| Free | 50/month | 7 days | 20 KB |
| Dev ($15/mo) | 2,000/month | 30 days | 200 KB |
| Pro ($39/mo) | 50,000/month | 30 days | 1 MB |

**Getting an API key:** Log in at [zephr.io/account](https://zephr.io/account), open the API Keys tab, and create a key. The raw key is shown exactly once. Copy it immediately.

**GitHub Actions:** Add `ZEPHR_API_KEY` as a repository secret and reference it in your workflow. The CLI picks it up automatically. Pass it explicitly in JS via `process.env.ZEPHR_API_KEY` and in Python via `os.environ.get("ZEPHR_API_KEY")`.

```yaml
env:
  ZEPHR_API_KEY: ${{ secrets.ZEPHR_API_KEY }}
```

---

## Security

- Encrypts on your device before any network call
- AES-GCM-256 with authenticated encryption and built-in tamper detection
- Keys never reach the server. They travel in the URL fragment ([RFC 3986 §3.5](https://datatracker.ietf.org/doc/html/rfc3986#section-3.5)), which browsers strip before sending requests.
- No plaintext logging. No analytics in the CLI or SDK.

[Full security model](https://zephr.io/security)

---

## Source layout

```
js/       CLI and JavaScript SDK (published to npm as `zephr`)
python/   Python SDK (published to PyPI as `zephr`)
```

This repository is automatically synced from the Zephr monorepo on every merge to `main`.

## Issues

[Open an issue](https://github.com/zephr-io/zephr-sdk/issues)

## License

MIT. See `js/LICENSE` and `python/LICENSE`.
