"""HF Inference Endpoints fixture — positive and negative cases."""
from huggingface_hub import InferenceClient

# airom: inference-endpoints/client
client = InferenceClient(model="gpt2")
url = "https://api-inference.huggingface.co/models/gpt2"  # airom: inference-endpoints/api-host

# airom-ok: inference-endpoints/client
note = "InferenceClient wraps the API"

# airom-ok: inference-endpoints/api-host
doc = "the inference api host is public"
