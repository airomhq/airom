"""Cohere usage fixture — positive and negative cases."""
import cohere

# airom: cohere/sdk-call
co = cohere.ClientV2(api_key="KEY")


def ask(question: str) -> str:
    # airom: cohere/sdk-call
    resp = co.chat(
        # airom: cohere/model-literal
        model="command-r-plus",
        messages=[{"role": "user", "content": question}],
    )
    return resp.message.content[0].text


# airom: cohere/model-literal
LEGACY = {"model": "command"}


# Negative cases below.

# airom-ok: cohere/model-literal
# model="command-r7b-12-2024"   (comment region — never scanned)

# airom-ok: cohere/model-literal
shell = "command not found"  # no model= position, not an id

# airom-ok: cohere/sdk-call
label = "co.chat helper"  # string mention, not a call in code
