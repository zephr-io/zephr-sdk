# OpenAI tool calling + Zephr

Secure credential handoff using OpenAI tool calling and Zephr.

## Setup

Requires Python 3.10+.

```bash
pip install -r requirements.txt
export OPENAI_API_KEY=sk-...
export ZEPHR_API_KEY=zeph_...      # required — the demo uses 15-minute expiry which needs Dev/Pro
```

## Run

```bash
python function_calling.py
```

The agent encrypts a credential locally via Zephr, stores only ciphertext on the server, and returns a one-time link. Compatible with GPT-5.4, GPT-5.4 mini, and GPT-5.4 nano.
