"""gpt4all usage fixture — positive and negative cases."""
from gpt4all import GPT4All  # airom: gpt4all/import

# airom: gpt4all/construct
model = GPT4All('mistral.gguf')

# A different package whose name merely starts the same way: a prefix match
# without a word boundary would claim gpt4all here.
# airom-ok: gpt4all/import
from gpt4allx import y

# airom-ok: gpt4all/construct
label = "note = 'gpt4all evaluation'"
