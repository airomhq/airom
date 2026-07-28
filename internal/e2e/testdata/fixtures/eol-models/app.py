"""A service still pinned to models the providers have scheduled for shutdown.

Exercises every lifecycle state the EOL overlay can report:
  gpt-4-32k     — retired: the API stopped serving it on 2025-06-06
  gpt-4-turbo   — deprecated: announced, shutdown 2026-10-23
  gpt-4o        — no catalog record, so no claim either way ("unknown")
"""

from openai import OpenAI

client = OpenAI()

# Long-context summarizer nobody migrated off. This call fails today.
summary = client.chat.completions.create(
    model="gpt-4-32k",
    messages=[{"role": "user", "content": "summarize"}],
)

# Still answering, but on a clock.
draft = client.chat.completions.create(
    model="gpt-4-turbo",
    messages=[{"role": "user", "content": "draft"}],
)

# Current default.
reply = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "reply"}],
)
