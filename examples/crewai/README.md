# CrewAI + Zephr

Multi-agent credential handoff using CrewAI and Zephr.

## Setup

Requires Python 3.10+.

```bash
pip install -r requirements.txt
export ZEPHR_API_KEY=zeph_...      # required — the demo uses 15-minute expiry which needs Dev/Pro
export OPENAI_API_KEY=sk-...
```

## Run

```bash
python zephr_crew.py
```

A provisioner agent creates a one-time secret with a 15-minute expiry and hint. A deployment agent retrieves it. The crew orchestrates the handoff — no shared state, no plaintext in logs.
