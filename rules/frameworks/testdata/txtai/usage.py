"""txtai usage fixture — positive and negative cases."""
from txtai import Embeddings  # airom: txtai/import

# airom: txtai/construct
emb = Embeddings({'path': 'sentence-transformers/all-MiniLM-L6-v2'})

# A different package whose name merely starts the same way: a prefix match
# without a word boundary would claim txtai here.
# airom-ok: txtai/import
from txtaix import z

# airom-ok: txtai/construct
label = "doc = 'txtai overview'"
