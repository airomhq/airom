"""Production entrypoint: the AI this project actually ships."""
from openai import OpenAI

client = OpenAI()


def summarize(text: str) -> str:
    return client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": text}],
    ).choices[0].message.content


def classify(text: str) -> str:
    # Also exercised from the test suite below — must stay a REAL component.
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": text}],
    ).choices[0].message.content
