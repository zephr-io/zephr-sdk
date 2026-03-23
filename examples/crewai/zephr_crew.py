"""
CrewAI + Zephr — multi-agent credential handoff.

Two agents in a crew exchange a credential through Zephr. The provisioning
agent creates a one-time secret; the deployment agent retrieves it. No
shared state, no plaintext in logs.

Requires:
    pip install zephr crewai crewai-tools
    export ZEPHR_API_KEY=zeph_...
    export OPENAI_API_KEY=sk-...
"""

import os
from typing import Optional, Type

from crewai import Agent, Crew, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

import zephr


class CreateSecretInput(BaseModel):
    """Input schema for ZephrCreateSecretTool."""
    secret: str = Field(description="The plaintext secret to encrypt. Max 2,048 UTF-8 bytes.")
    expiry: int = Field(default=60, description="Expiry in minutes: 5, 15, 30, 60, 1440, 10080, 43200.")
    hint: Optional[str] = Field(default=None, description="Plaintext label for routing/audit.")
    callback_url: Optional[str] = Field(default=None, description="HTTPS webhook URL for lifecycle events.")
    callback_secret: Optional[str] = Field(default=None, description="HMAC-SHA256 signing secret for webhook.")


class RetrieveSecretInput(BaseModel):
    """Input schema for ZephrRetrieveSecretTool."""
    link: str = Field(description="Full Zephr link including the encryption key in the URL fragment.")


class ZephrCreateSecretTool(BaseTool):
    name: str = "zephr_create_secret"
    description: str = (
        "Encrypt a secret client-side and store only ciphertext on Zephr. "
        "Returns a one-time link. The server never holds the encryption key."
    )
    args_schema: Type[BaseModel] = CreateSecretInput

    def _run(self, secret: str, expiry: int = 60, hint: str | None = None,
             callback_url: str | None = None, callback_secret: str | None = None) -> str:
        kwargs = {
            "expiry": expiry,
            "api_key": os.environ.get("ZEPHR_API_KEY"),
        }
        if hint:
            kwargs["hint"] = hint
        if callback_url:
            kwargs["callback_url"] = callback_url
        if callback_secret:
            kwargs["callback_secret"] = callback_secret

        result = zephr.create_secret(secret, **kwargs)
        return f"Link: {result['full_link']}\nExpires: {result['expires_at']}"


class ZephrRetrieveSecretTool(BaseTool):
    name: str = "zephr_retrieve_secret"
    description: str = (
        "Retrieve and decrypt a one-time secret from Zephr. "
        "The record is permanently destroyed on first access."
    )
    args_schema: Type[BaseModel] = RetrieveSecretInput

    def _run(self, link: str) -> str:
        result = zephr.retrieve_secret(link, api_key=os.environ.get("ZEPHR_API_KEY"))
        lines = [f"Plaintext: {result['plaintext']}"]
        if result.get("hint"):
            lines.append(f"Hint: {result['hint']}")
        return "\n".join(lines)


# ── Agents ───────────────────────────────────────────────────────────

provisioner = Agent(
    role="Credential Provisioner",
    goal="Securely create and share one-time credentials for deployment.",
    backstory="You manage production credentials and share them securely via Zephr one-time links.",
    tools=[ZephrCreateSecretTool()],
)

deployer = Agent(
    role="Deployment Agent",
    goal="Retrieve credentials and use them for deployment.",
    backstory="You receive Zephr one-time links and retrieve credentials for deployment tasks.",
    tools=[ZephrRetrieveSecretTool()],
)


# ── Tasks ────────────────────────────────────────────────────────────

create_task = Task(
    description=(
        "Create a one-time secret containing the database password 'pg-prod-s3cret!' "
        "with hint DB_PASSWORD_PROD and 15-minute expiry. Return the full link."
    ),
    expected_output="A Zephr one-time link for the database credential.",
    agent=provisioner,
)

retrieve_task = Task(
    description="Retrieve the secret from the Zephr link provided by the provisioner and confirm the credential.",
    expected_output="The decrypted database credential and its hint.",
    agent=deployer,
)


# ── Crew ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    crew = Crew(
        agents=[provisioner, deployer],
        tasks=[create_task, retrieve_task],
        verbose=True,
    )
    result = crew.kickoff()
    print("\n=== Final Result ===")
    print(result)
