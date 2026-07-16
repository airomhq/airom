"""OpenAI usage fixture — positive and negative cases."""
import os
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def ask(question: str) -> str:
    # airom: openai/chat-call
    resp = client.chat.completions.create(
        # airom: openai/model-literal
        model="gpt-4o",
        temperature=0.2,
        max_tokens=1024,
        messages=[{"role": "user", "content": question}],
    )
    return resp.choices[0].message.content


def reason(question: str) -> str:
    # airom: openai/model-literal
    payload = {"model": "o3-mini", "input": question}
    return client.responses.create(**payload).output_text


# Negative cases below.

# airom-ok: openai/model-literal
# model="gpt-4o-mini"   (this line is a comment — never scanned)

# airom-ok: openai/model-literal
adapter = "gpt-neo-125m"  # not an OpenAI id and not in a model= position

# airom-ok: openai/chat-call
existing = client.chat.completions.retrieve("resp_123")
