"""Voyage AI embeddings usage fixture — positive and negative cases."""
import voyageai

# airom: voyage/embed-call
vo = voyageai.Client()


def embed(texts: list[str]) -> list[list[float]]:
    # airom: voyage/embed-call
    result = vo.embed(
        texts,
        # airom: voyage/model-literal
        model="voyage-3-large",
    )
    return result.embeddings


# airom: voyage/model-literal
CODE = {"model": "voyage-code-3"}


# Negative cases below.

# airom-ok: voyage/model-literal
# model="voyage-finance-2"   (comment region — never scanned)

# airom-ok: voyage/model-literal
trip = "a long voyage-3 journey abroad"  # 'voyage-' is mid-string, not at the quote boundary

# airom-ok: voyage/embed-call
docs = "see vo.embed() and voyageai.Client() in the README"  # string mention, not a code call
