"""Weaviate usage fixture — positive and negative cases."""
import weaviate  # airom: weaviate/import

# airom: weaviate/client
client = weaviate.connect_to_local()
legacy = weaviate.Client("http://localhost:8080")  # airom: weaviate/client

# airom-ok: weaviate/import
note = "weaviate cloud console"

# airom-ok: weaviate/client
doc = "weaviate.Client migration"
