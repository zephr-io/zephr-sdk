"""
OpenAI tool calling + Zephr — secure credential handoff.

Shows an OpenAI-powered agent using Zephr to create and retrieve
one-time secrets via tool calling. Compatible with GPT-5.4,
GPT-5.4 mini, and GPT-5.4 nano.

Requires:
    pip install zephr openai
    export OPENAI_API_KEY=sk-...
    export ZEPHR_API_KEY=zeph_...      # optional for testing
"""

import json
import os

import openai
import zephr

# ── Tool definitions ─────────────────────────────────────────────────

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "zephr_create_secret",
            "description": (
                "Encrypt a secret client-side and store only ciphertext on Zephr. "
                "Returns a one-time link. The server never holds the encryption key."
            ),
            "parameters": {
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
    },
    {
        "type": "function",
        "function": {
            "name": "zephr_retrieve_secret",
            "description": (
                "Retrieve and decrypt a one-time secret from Zephr. "
                "The record is permanently destroyed on first access."
            ),
            "parameters": {
                "type": "object",
                "required": ["link"],
                "properties": {
                    "link": {"type": "string", "description": "Full Zephr link with key in fragment."},
                },
            },
        },
    },
]


# ── Tool execution ───────────────────────────────────────────────────

def call_tool(name: str, args: dict) -> str:
    api_key = os.environ.get("ZEPHR_API_KEY")

    if name == "zephr_create_secret":
        kwargs = {"expiry": args.get("expiry", 60), "api_key": api_key}
        for field in ("hint", "callback_url", "callback_secret"):
            if args.get(field):
                kwargs[field] = args[field]
        result = zephr.create_secret(args["secret"], **kwargs)
        return json.dumps({"link": result.full_link, "expires_at": result.expires_at})

    if name == "zephr_retrieve_secret":
        result = zephr.retrieve_secret(args["link"], api_key=api_key)
        return json.dumps({"plaintext": result.plaintext, "hint": result.hint})

    return json.dumps({"error": f"Unknown tool: {name}"})


# ── Agent loop ───────────────────────────────────────────────────────

def run_agent(user_message: str) -> str:
    client = openai.OpenAI()
    messages = [
        {"role": "system", "content": "You are a helpful agent with access to Zephr for secure secret sharing."},
        {"role": "user", "content": user_message},
    ]

    while True:
        response = client.chat.completions.create(
            model="gpt-5.4",
            messages=messages,
            tools=TOOLS,
        )

        choice = response.choices[0]

        if choice.finish_reason == "stop":
            return choice.message.content

        if choice.finish_reason == "tool_calls":
            messages.append(choice.message)
            for tool_call in choice.message.tool_calls:
                result = call_tool(
                    tool_call.function.name,
                    json.loads(tool_call.function.arguments),
                )
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result,
                })


# ── Demo ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Creating secret ===")
    response = run_agent(
        "Store the API key 'sk-test-abc123' as a one-time secret with hint OPENAI_KEY and 15-minute expiry. "
        "Return the link."
    )
    print(response)
