"""OpenAI embeddings usage fixture — positive and negative cases."""
import os
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def embed(text: str) -> list[float]:
    # airom: openai/embedding-literal
    resp = client.embeddings.create(model="text-embedding-3-small", input=text)
    return resp.data[0].embedding


# airom: openai/embedding-literal
LEGACY = {"model": "text-embedding-ada-002"}


# Negative cases below.

# airom-ok: openai/embedding-literal
# model="text-embedding-3-large"   (comment region — never scanned)

# airom-ok: openai/embedding-literal
chat = "gpt-4o"  # a chat model id, not an embedding id
