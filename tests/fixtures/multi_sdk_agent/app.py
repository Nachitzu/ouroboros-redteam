"""Fixture: multi-SDK Python + TypeScript + template/config prompts."""

from __future__ import annotations

import textwrap

import litellm
from google import genai
from google.genai import types
from langchain_core.messages import SystemMessage
from langchain_core.prompts import ChatPromptTemplate
from pydantic_ai import Agent

SYSTEM_PROMPT: str = textwrap.dedent(
    """
    You are a multi-SDK security auditing assistant. Always verify inputs carefully
    before answering any engineering question from the caller.
    """
).strip()

IMPLICIT_PROMPT = (
    "You are an incident triage helper that summarizes alerts accurately "
    "and returns concise operational guidance for responders."
)

pydantic_agent = Agent(
    "openai:gpt-4o-mini",
    system_prompt=(
        "You are a PydanticAI compliance reviewer. Inspect each submission thoroughly "
        "and cite exact policy clauses in your response."
    ),
)


def call_gemini(user_query: str) -> str:
    client = genai.Client()
    cfg = types.GenerateContentConfig(
        system_instruction=(
            "You are a Gemini architecture assistant. Answer questions clearly using "
            "only verified technical documentation and avoid speculation."
        )
    )
    resp = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=user_query,
        config=cfg,
    )
    return resp.text


def call_litellm(user_query: str) -> str:
    resp = litellm.completion(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a LiteLLM routing assistant. Provide accurate summaries of "
                    "incoming requests without fabricating missing facts."
                ),
            },
            {"role": "user", "content": user_query},
        ],
    )
    return resp.choices[0].message.content


def build_langchain_prompts() -> tuple[SystemMessage, ChatPromptTemplate]:
    sys_msg = SystemMessage(
        content=(
            "You are a LangChain document analyst. Summarize key technical details "
            "from the supplied passages accurately and concisely."
        )
    )
    tmpl = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You are a LangChain template assistant designed to review pull requests "
                "for correctness, clarity, and adherence to coding standards.",
            ),
            ("human", "{input}"),
        ]
    )
    return sys_msg, tmpl
