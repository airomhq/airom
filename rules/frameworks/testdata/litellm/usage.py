"""LiteLLM usage fixture — positive and negative cases."""
import litellm  # airom: litellm/import

# airom: litellm/call
resp = litellm.completion(model="gpt-4o", messages=[])

# airom-ok: litellm/import
note = "litellm proxy config"

# airom-ok: litellm/call
label = "litellm.completion tutorial"
