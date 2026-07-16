"""HF Transformers usage fixture — positive and negative cases."""
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline  # airom: transformers/import

# airom: transformers/auto-class
model = AutoModelForCausalLM.from_pretrained("gpt2")
tok = AutoTokenizer.from_pretrained("gpt2")  # airom: transformers/auto-class
gen = pipeline("text-generation")  # airom: transformers/auto-class

# airom-ok: transformers/import
note = "transformers library guide"

# airom-ok: transformers/auto-class
doc = "AutoModel usage tips"
