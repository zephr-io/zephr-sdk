"""
LangChain tools for Zephr — zero-knowledge secret transport.

Drop these tools into any LangChain agent to give it secure credential
handoff. Secrets are encrypted client-side; the server never sees plaintext.

    from zephr_tools import ZephrCreateSecretTool, ZephrRetrieveSecretTool
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(model="gpt-5.4")
    llm_with_tools = llm.bind_tools([ZephrCreateSecretTool(), ZephrRetrieveSecretTool()])

Requires:
    pip install zephr langchain-core langchain-openai
"""

import os
from typing import Optional

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

import zephr


class CreateSecretInput(BaseModel):
    secret: str = Field(description="The plaintext secret to encrypt. Max 2,048 UTF-8 bytes.")
    expiry: int = Field(default=60, description="Expiry in minutes: 5, 15, 30, 60, 1440, 10080, 43200.")
    hint: Optional[str] = Field(default=None, description="Plaintext label for routing/audit (1-128 printable ASCII).")
    callback_url: Optional[str] = Field(default=None, description="HTTPS webhook URL for consumption/expiry events.")
    callback_secret: Optional[str] = Field(default=None, description="HMAC-SHA256 signing secret for the webhook.")


class RetrieveSecretInput(BaseModel):
    link: str = Field(description="Full Zephr link including the encryption key in the URL fragment.")


class ZephrCreateSecretTool(BaseTool):
    """Encrypt a secret client-side and store only ciphertext on Zephr.
    Returns a one-time link. The server never holds the encryption key."""

    name: str = "zephr_create_secret"
    description: str = (
        "Encrypt a secret locally and upload only ciphertext to Zephr. "
        "Returns a one-time link that is permanently destroyed on first retrieval. "
        "The server never sees the plaintext or encryption key."
    )
    args_schema: type[BaseModel] = CreateSecretInput

    def _run(self, secret: str, expiry: int = 60, hint: str | None = None,
             callback_url: str | None = None, callback_secret: str | None = None) -> str:
        kwargs = {"expiry": expiry, "api_key": os.environ.get("ZEPHR_API_KEY")}
        if hint:
            kwargs["hint"] = hint
        if callback_url:
            kwargs["callback_url"] = callback_url
        if callback_secret:
            kwargs["callback_secret"] = callback_secret

        result = zephr.create_secret(secret, **kwargs)

        lines = [f"Link: {result['full_link']}", f"Expires: {result['expires_at']}"]
        if hint:
            lines.append(f"Hint: {hint}")
        return "\n".join(lines)


class ZephrRetrieveSecretTool(BaseTool):
    """Retrieve and decrypt a one-time secret from Zephr.
    The record is permanently destroyed on first access."""

    name: str = "zephr_retrieve_secret"
    description: str = (
        "Retrieve and decrypt a one-time secret from Zephr. "
        "The record is permanently destroyed on first access. "
        "A second call with the same link fails."
    )
    args_schema: type[BaseModel] = RetrieveSecretInput

    def _run(self, link: str) -> str:
        result = zephr.retrieve_secret(link, api_key=os.environ.get("ZEPHR_API_KEY"))
        lines = [result["plaintext"]]
        if result.get("hint"):
            lines.append(f"Hint: {result['hint']}")
        return "\n".join(lines)
