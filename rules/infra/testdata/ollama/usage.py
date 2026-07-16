"""Ollama usage fixture — positive and negative cases."""
import ollama  # airom: ollama/import
import os

# airom: ollama/serve-endpoint
host = os.environ["OLLAMA_HOST"]
base = "http://localhost:11434"  # airom: ollama/serve-endpoint

# airom: ollama/client
client = ollama.Client(host=base)
resp = ollama.chat(model="llama3", messages=[])  # airom: ollama/client

# airom-ok: ollama/import
note = "ollama runs models locally"

# airom-ok: ollama/serve-endpoint
doc = "set the host env var before start"

# airom-ok: ollama/client
txt = "ollama.Client wraps the REST API"
