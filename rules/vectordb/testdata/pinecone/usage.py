"""Pinecone usage fixture — positive and negative cases."""
from pinecone import Pinecone  # airom: pinecone/import

# airom: pinecone/client
pc = Pinecone(api_key="...")
idx = pinecone.Index("my-index")  # airom: pinecone/client

# airom-ok: pinecone/import
note = "pinecone quickstart"

# airom-ok: pinecone/client
doc = "Pinecone service status"
