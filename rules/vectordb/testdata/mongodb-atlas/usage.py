"""MongoDB Atlas vector-search usage fixture — positive and negative cases."""
pipeline = [
    # airom: mongodb-atlas/vector-search
    {"$vectorSearch": {"index": "vidx", "path": "embedding", "queryVector": q}},
]
index_def = {
    # airom: mongodb-atlas/vector-index
    "fields": [{"type": "vector", "numDimensions": 768, "similarity": "cosine"}],
}

# airom-ok: mongodb-atlas/vector-search
note = "use $vectorSearch for ANN queries"

# airom-ok: mongodb-atlas/vector-index
doc = "numDimensions must match the model"
