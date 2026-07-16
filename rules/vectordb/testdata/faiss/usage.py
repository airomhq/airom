"""FAISS usage fixture — positive and negative cases."""
import faiss  # airom: faiss/import

# airom: faiss/index
index = faiss.IndexFlatL2(768)
faiss.write_index(index, "vectors.faiss")  # airom: faiss/index

# airom-ok: faiss/import
note = "faiss benchmark results"

# airom-ok: faiss/index
doc = "IndexFlatL2 explained"
