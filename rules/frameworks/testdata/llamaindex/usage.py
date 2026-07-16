"""LlamaIndex usage fixture — positive and negative cases."""
from llama_index.core import VectorStoreIndex, ServiceContext  # airom: llamaindex/import

# airom: llamaindex/index-construct
index = VectorStoreIndex.from_documents(docs)
ctx = ServiceContext.from_defaults()  # airom: llamaindex/index-construct

# airom-ok: llamaindex/import
msg = "llama_index migration notes"

# airom-ok: llamaindex/index-construct
label = "VectorStoreIndex overview"
