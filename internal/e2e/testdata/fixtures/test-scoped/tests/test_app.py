"""Test suite. The models named ONLY here are test scaffolding."""
import anthropic
from app import classify, summarize


def test_summarize():
    assert summarize("hello")


def test_classify():
    assert classify("hello")


def test_classify_directly():
    # gpt-4o-mini is named HERE and in app.py. A model that production code
    # reaches is production AI even when a test also reaches it, so this must
    # NOT be scoped out.
    from openai import OpenAI

    OpenAI().chat.completions.create(
        model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}]
    )


def test_legacy_baseline():
    # Named only in tests -> test-scoped.
    anthropic.Anthropic().messages.create(
        model="claude-1.0", max_tokens=1, messages=[]
    )
