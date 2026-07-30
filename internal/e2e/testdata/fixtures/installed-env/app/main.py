"""A deployed application: shipped code, no manifest.

This is what a container image, a virtualenv, or an unpacked PyInstaller
bundle actually looks like. There is no requirements.txt and no
pyproject.toml — those stayed behind in the source repo. The only record of
which versions are present is the installed metadata in site-packages.
"""

import chromadb
import langchain
from openai import OpenAI

client = OpenAI()


def answer(question: str) -> str:
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": question}],
    )
    return resp.choices[0].message.content
