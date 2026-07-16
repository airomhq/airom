"""Redis vector-search usage fixture — positive and negative cases."""
from redis.commands.search.field import VectorField, TextField

# airom: redis-vector/vectorfield
schema = (VectorField("embedding", "FLAT", {"TYPE": "FLOAT32", "DIM": 768}),)

# airom: redis-vector/ft-create
cmd = "FT.CREATE idx ON HASH PREFIX 1 doc: SCHEMA embedding VECTOR FLAT 6 TYPE FLOAT32"

# airom-ok: redis-vector/vectorfield
note = "VectorField schema notes"

# airom-ok: redis-vector/ft-create
doc = "FT.CREATE builds a search index"
