"""Mistral AI usage fixture — positive and negative cases."""
import os
from mistralai import Mistral

client = Mistral(api_key=os.environ["MISTRAL_API_KEY"])


def ask(question: str) -> str:
    # airom: mistral/sdk-call
    resp = client.chat.complete(
        # airom: mistral/model-literal
        model="mistral-large-latest",
        messages=[{"role": "user", "content": question}],
    )
    return resp.choices[0].message.content


# airom: mistral/model-literal
OSS = {"model": "open-mixtral-8x22b"}
# airom: mistral/model-literal
CODE = {"model": "codestral-latest"}


# Negative cases below.

# airom-ok: mistral/model-literal
# model="mixtral-8x7b-instruct"   (comment region — never scanned)

# airom-ok: mistral/model-literal
drink = "mistral-wind-cocktail"  # not a model= position

# airom-ok: mistral/sdk-call
doc = "see chat.completions docs, not chat.complete here"
