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

# ── Regression: the operators mean pgvector only inside SQL ────────────────
# Each line below produced a pgvector finding before the rule required SQL
# context; together this class accounted for 437 occurrences on one machine.

# airom-ok: pgvector/distance-op
prose = "the codec maps text <-> bytes"

# airom-ok: pgvector/distance-op
spaceship = "sort_by { |a, b| a <=> b }"    # Ruby/Rust, not Postgres

# airom-ok: pgvector/distance-op
diagram = "client <-> gateway <-> service"

# The client API — how most Python projects actually call pgvector.
# airom: pgvector/distance-fn
q = session.scalars(select(Item).order_by(Item.embedding.l2_distance([3, 1, 2])))

# airom: pgvector/distance-fn
near = select(Doc).order_by(Doc.vec.cosine_distance(query_vec)).limit(5)

# airom-ok: pgvector/distance-fn
unrelated = "compute the l2 distance between the two points"
