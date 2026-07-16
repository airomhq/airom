"""Anthropic usage fixture — positive and negative cases."""
import os
import anthropic

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])


def ask(question: str) -> str:
    # airom: anthropic/messages-call
    resp = client.messages.create(
        # airom: anthropic/model-literal
        model="claude-3-5-sonnet-20241022",
        max_tokens=1024,
        temperature=0.0,
        messages=[{"role": "user", "content": question}],
    )
    return resp.content[0].text


def ask_v4(question: str) -> str:
    # airom: anthropic/model-literal
    cfg = {"model": "claude-sonnet-4-5", "max_tokens": 2048}
    return client.messages.create(**cfg, messages=[]).content[0].text


# Negative cases below.

# airom-ok: anthropic/model-literal
# model="claude-3-opus-20240229"   (comment region — never scanned)

# airom-ok: anthropic/model-literal
nickname = "claude-the-intern"  # not a model= position

# airom-ok: anthropic/messages-call
history = client.messages.list()
