"""vLLM (library) usage fixture — positive and negative cases."""
from vllm import LLM, SamplingParams  # airom: vllm/import

# airom: vllm/llm-construct
llm = LLM(model="meta-llama/Llama-3-8b")
params = SamplingParams(temperature=0.7)  # airom: vllm/llm-construct

# airom-ok: vllm/import
note = "vllm throughput benchmark"

# airom-ok: vllm/llm-construct
doc = "SamplingParams reference"
