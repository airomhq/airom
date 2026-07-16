"""Milvus usage fixture — positive and negative cases."""
from pymilvus import connections, Collection, MilvusClient  # airom: milvus/import

# airom: milvus/connect
connections.connect(host="localhost", port="19530")
client = MilvusClient(uri="http://localhost:19530")  # airom: milvus/connect

# airom-ok: milvus/import
note = "pymilvus tutorial"

# airom-ok: milvus/connect
doc = "connections.connect docs"
