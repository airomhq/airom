"""Chroma usage fixture — positive and negative cases."""
import chromadb  # airom: chroma/import

# airom: chroma/client
client = chromadb.PersistentClient(path="./db")
c2 = chromadb.Client()  # airom: chroma/client

# airom-ok: chroma/import
note = "chromadb setup guide"

# airom-ok: chroma/client
doc = "chromadb.Client explained"
