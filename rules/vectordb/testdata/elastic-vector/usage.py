"""Elasticsearch vector-search usage fixture — positive and negative cases."""
mapping = {
    # airom: elastic-vector/dense-vector
    "embedding": {"type": "dense_vector", "dims": 768},
}
query = {
    # airom: elastic-vector/knn-search
    "knn": {"field": "embedding", "query_vector": [0.1, 0.2]},
}

# airom-ok: elastic-vector/dense-vector
note = "dense_vector overview blog"

# airom-ok: elastic-vector/knn-search
doc = "query_vector param docs"
