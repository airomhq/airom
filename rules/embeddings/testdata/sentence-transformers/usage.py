"""sentence-transformers usage fixture — positive and negative cases."""
from sentence_transformers import SentenceTransformer

# airom: sentence-transformers/constructor
# airom: sentence-transformers/model-literal
encoder = SentenceTransformer("all-MiniLM-L6-v2")


def named() -> str:
    # airom: sentence-transformers/model-literal
    return "sentence-transformers/all-mpnet-base-v2"


# Negative cases below.

# airom-ok: sentence-transformers/constructor
# SentenceTransformer("all-MiniLM-L12-v2")   (comment — never scanned)

# airom-ok: sentence-transformers/model-literal
other = "bert-base-nli-mean-tokens"  # SBERT-adjacent but not an all-* / multi-qa name

# airom-ok: sentence-transformers/constructor
factory = "SentenceTransformerFactory"  # no call, no string arg
