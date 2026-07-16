"""BGE / E5 embedding-model usage fixture — positive and negative cases."""
from sentence_transformers import SentenceTransformer

# airom: bge-e5/bge-literal
bge = SentenceTransformer("BAAI/bge-large-en-v1.5")

# airom: bge-e5/e5-literal
e5 = SentenceTransformer("intfloat/e5-large-v2")

# airom: bge-e5/e5-literal
MULTI = {"model": "intfloat/multilingual-e5-large"}


# Negative cases below.

# airom-ok: bge-e5/bge-literal
# "BAAI/bge-small-en-v1.5"   (comment region — never scanned)

# airom-ok: bge-e5/bge-literal
org = "BAAI/AquilaChat-7B"  # BAAI org but not a bge- model

# airom-ok: bge-e5/e5-literal
note = "e5-2680 xeon cpu"  # Intel part number, not an embedding id (no closing quote after token)
