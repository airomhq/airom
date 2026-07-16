"""Standalone generation-parameter config-as-code fixture (Python settings).

Uses both top-level `key = value` assignments (toml/ini/py shape) and a dict
with `"key": value` entries (yaml/json shape) so both separators are exercised.
"""

# airom: aiconfig/sampling
temperature = 0.7
# airom: aiconfig/sampling
top_p = 0.9

# airom: aiconfig/token-limits
max_tokens = 512
# airom: aiconfig/token-limits
context_window = 8192

# airom: aiconfig/decoding
seed = 42
# airom: aiconfig/decoding
response_format = "json_object"

generation = {
    "temperature": 0.2,  # airom: aiconfig/sampling
    "max_output_tokens": 1024,  # airom: aiconfig/token-limits
    "stop": ["\n\n"],  # airom: aiconfig/decoding
}

# Negative cases — keyword present, anchored pattern must reject.
# airom-ok: aiconfig/sampling
temperature_note = "tune later"

# airom-ok: aiconfig/token-limits
description = "max_tokens is a soft limit"

# airom-ok: aiconfig/decoding
seed_comment = "no fixed seed"
