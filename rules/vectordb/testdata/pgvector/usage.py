"""pgvector usage fixture — SQL embedded in Python strings."""
setup = "CREATE EXTENSION IF NOT EXISTS vector"  # airom: pgvector/create-extension
ddl = "CREATE TABLE items (id bigserial, embedding vector(768))"  # airom: pgvector/vector-column
knn = "SELECT * FROM items ORDER BY embedding <-> %s LIMIT 5"  # airom: pgvector/distance-op

# airom-ok: pgvector/create-extension
note = "run create extension for uuid support"

# airom-ok: pgvector/vector-column
doc = "the vector column stores embeddings"

# airom-ok: pgvector/distance-op
txt = "a < b and c > d comparison"
