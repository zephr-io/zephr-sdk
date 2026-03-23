# Anthropic tool_use + Zephr

Agent-to-agent secret handoff using Claude's native tool_use and Zephr.

## Setup

Requires Python 3.10+.

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
export ZEPHR_API_KEY=zeph_...      # required — the demo uses 15-minute expiry which needs Dev/Pro
```

## Run

```bash
python agent_handoff.py
```

Agent A encrypts a database password with a 15-minute expiry and hint. Agent B retrieves and decrypts it. The server never sees the plaintext.

## How it works

1. Agent A calls `zephr_create_secret` via tool_use — encrypts locally, uploads ciphertext
2. The one-time link is passed to Agent B through the orchestration layer
3. Agent B calls `zephr_retrieve_secret` — fetches ciphertext, decrypts locally
4. The server record is permanently destroyed on first retrieval
