"""
Anthropic tool_use — agent-to-agent secret handoff via Zephr.

Demonstrates two Claude agents exchanging a credential through a Zephr
one-time link. Agent A creates the secret with a webhook callback;
Agent B retrieves it. The orchestrator is notified via the webhook when
the handoff completes.

Requires:
    pip install zephr anthropic
    export ANTHROPIC_API_KEY=sk-ant-...
    export ZEPHR_API_KEY=zeph_...        # optional for testing
"""

import json
import os

import anthropic
import zephr

# ── Tool definitions ─────────────────────────────────────────────────

TOOLS = [
    {
        "name": "zephr_create_secret",
        "description": (
            "Encrypt a secret client-side and store only ciphertext on Zephr. "
            "Returns a one-time link. The server never holds the encryption key."
        ),
        "input_schema": {
            "type": "object",
            "required": ["secret"],
            "properties": {
                "secret": {"type": "string", "description": "Plaintext to encrypt (max 2,048 UTF-8 bytes)."},
                "expiry": {"type": "integer", "description": "Expiry in minutes. Default 60."},
                "hint": {"type": "string", "description": "Plaintext label for routing/audit."},
                "callback_url": {"type": "string", "description": "HTTPS webhook URL for lifecycle events."},
                "callback_secret": {"type": "string", "description": "HMAC-SHA256 signing secret for webhook."},
            },
        },
    },
    {
        "name": "zephr_retrieve_secret",
        "description": (
            "Retrieve and decrypt a one-time secret from Zephr. "
            "The record is permanently destroyed on first access."
        ),
        "input_schema": {
            "type": "object",
            "required": ["link"],
            "properties": {
                "link": {"type": "string", "description": "Full Zephr link with key in fragment."},
            },
        },
    },
]


# ── Tool execution ───────────────────────────────────────────────────

def execute_tool(name: str, args: dict) -> str:
    api_key = os.environ.get("ZEPHR_API_KEY")

    if name == "zephr_create_secret":
        kwargs = {"expiry": args.get("expiry", 60), "api_key": api_key}
        for field in ("hint", "callback_url", "callback_secret"):
            if args.get(field):
                kwargs[field] = args[field]
        result = zephr.create_secret(args["secret"], **kwargs)
        return json.dumps({"link": result["full_link"], "expires_at": result["expires_at"]})

    if name == "zephr_retrieve_secret":
        result = zephr.retrieve_secret(args["link"], api_key=api_key)
        return json.dumps({"plaintext": result["plaintext"], "hint": result.get("hint")})

    return json.dumps({"error": f"Unknown tool: {name}"})


# ── Agent loop ───────────────────────────────────────────────────────

def run_agent(system_prompt: str, user_message: str) -> str:
    """Run a single-turn agent loop with tool use."""
    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": user_message}]

    while True:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=system_prompt,
            tools=TOOLS,
            messages=messages,
        )

        # If the model is done, return the text.
        if response.stop_reason == "end_turn":
            return "".join(b.text for b in response.content if b.type == "text")

        # Process tool calls.
        messages.append({"role": "assistant", "content": response.content})
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                result = execute_tool(block.name, block.input)
                tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": result})
        messages.append({"role": "user", "content": tool_results})


# ── Demo ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Agent A: creates a secret and returns the link.
    print("=== Agent A: Creating secret ===")
    link_response = run_agent(
        system_prompt="You are Agent A. Create secrets when asked and return the link.",
        user_message=(
            "Store the database password 'pg-prod-s3cret!' as a one-time secret "
            "with hint DB_PASSWORD_PROD and 15-minute expiry. Return the link."
        ),
    )
    print(link_response)

    # In a real pipeline, Agent A passes the link to Agent B via a
    # message queue, task payload, or orchestration event.

    # Agent B: retrieves and uses the secret.
    print("\n=== Agent B: Retrieving secret ===")
    retrieve_response = run_agent(
        system_prompt="You are Agent B. Retrieve secrets when given a Zephr link.",
        user_message=f"Retrieve the secret from this link and tell me what it contains:\n{link_response}",
    )
    print(retrieve_response)
