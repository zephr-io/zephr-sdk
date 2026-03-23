# LangChain + Zephr

Drop-in LangChain tools for zero-knowledge secret transport between agents.

## Setup

Requires Python 3.10+.

```bash
pip install -r requirements.txt
export ZEPHR_API_KEY=zeph_...      # optional — without it: 3 creates/day, 1h max expiry, no sub-hour expiry
export OPENAI_API_KEY=sk-...
```

## Usage

```python
from langchain_openai import ChatOpenAI
from zephr_tools import ZephrCreateSecretTool, ZephrRetrieveSecretTool

llm = ChatOpenAI(model="gpt-5.4")
tools = [ZephrCreateSecretTool(), ZephrRetrieveSecretTool()]
llm_with_tools = llm.bind_tools(tools)

response = llm_with_tools.invoke(
    "Store the API key sk-test-abc123 as a one-time secret with hint OPENAI_KEY and 1-hour expiry."
)
```

## Webhook callback

```python
response = llm_with_tools.invoke(
    "Store my database password 'pg-secret-xyz' with a 5-minute expiry, "
    "hint DB_PROD, and a webhook callback to https://my-orchestrator.example.com/events "
    "with signing secret 'my-hmac-secret'."
)
```

When the secret is retrieved, Zephr POSTs a signed event to the callback URL. The orchestrator confirms the handoff without polling.
