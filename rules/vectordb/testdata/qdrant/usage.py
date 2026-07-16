"""Qdrant usage fixture — positive and negative cases."""
from qdrant_client import QdrantClient  # airom: qdrant/import

# airom: qdrant/client
client = QdrantClient(url="http://localhost:6333")

# airom-ok: qdrant/import
note = "qdrant_client changelog"

# airom-ok: qdrant/client
doc = "QdrantClient reference"
