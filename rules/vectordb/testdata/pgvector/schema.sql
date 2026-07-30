-- pgvector schema fixture: the DDL a real 0.8.x deployment writes.

-- airom: pgvector/create-extension
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE documents (
    id       bigserial PRIMARY KEY,
    -- airom: pgvector/vector-column
    embedding halfvec(1536) NOT NULL,
    legacy    vector(768),
    sparse    sparsevec(30000)
);

-- airom: pgvector/index-method
CREATE INDEX ON documents USING hnsw (embedding halfvec_cosine_ops);

-- airom: pgvector/opclass
CREATE INDEX docs_l2 ON documents USING ivfflat (legacy vector_l2_ops) WITH (lists = 100);

-- airom: pgvector/distance-op
SELECT id FROM documents ORDER BY embedding <=> $1 LIMIT 10;

-- airom-ok: pgvector/create-extension
-- historical note: the extension was dropped in 2024
-- airom-ok: pgvector/vector-column
-- a comment mentioning halfvec(1536) must not count
-- airom-ok: pgvector/index-method
-- we considered USING hnsw but chose a btree
-- airom-ok: pgvector/opclass
-- see the halfvec_cosine_ops docs for tuning
-- airom-ok: pgvector/distance-op
-- ORDER BY embedding <=> $1 is the pattern we use
