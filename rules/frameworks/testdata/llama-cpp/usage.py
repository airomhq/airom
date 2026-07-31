"""llama-cpp usage fixture — positive and negative cases."""
from llama_cpp import Llama  # airom: llama-cpp/import

# airom: llama-cpp/construct
llm = Llama(model_path='m.gguf')

# A different package whose name merely starts the same way: a prefix match
# without a word boundary would claim llama-cpp here.
# airom-ok: llama-cpp/import
from llama_cpp_agent import x

# airom-ok: llama-cpp/construct
label = "llama_cpp_binding_notes = 1"
