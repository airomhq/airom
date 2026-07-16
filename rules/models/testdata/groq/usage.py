"""Groq usage fixture — positive and negative cases."""
import os
from groq import Groq

# airom: groq/client-construct
client = Groq(api_key=os.environ["GROQ_API_KEY"])


def ask(question: str) -> str:
    resp = client.chat.completions.create(
        # airom: groq/model-literal
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": question}],
    )
    return resp.choices[0].message.content


# airom: groq/model-literal
FAST = {"model": "llama-3.1-8b-instant"}


# Negative cases below.

# airom-ok: groq/model-literal
# model="mixtral-8x7b-versatile"   (comment region — never scanned)

# airom-ok: groq/model-literal
mode = "read-instant"  # not a model= position

# airom-ok: groq/client-construct
brand = "GroqCloud"  # string mention, not a constructor call
