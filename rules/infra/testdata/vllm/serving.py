"""vLLM serving-infra fixture — commands captured in strings."""
# airom: vllm/serve
cmd = "vllm serve meta-llama/Llama-3-8b --port 8000"

# airom: vllm/api-server
mod = "python -m vllm.entrypoints.openai.api_server --model gpt2"

# airom: vllm/served-model-name
flag = "--served-model-name my-model --dtype auto"

# airom-ok: vllm/serve
note = "our vllm service handles batching"

# airom-ok: vllm/api-server
doc = "the api_server exposes an OpenAI API"

# airom-ok: vllm/served-model-name
txt = "set the served model name flag"
