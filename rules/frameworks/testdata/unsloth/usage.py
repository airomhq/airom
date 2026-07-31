"""unsloth usage fixture — positive and negative cases."""
from unsloth import FastLanguageModel  # airom: unsloth/import

# airom: unsloth/construct
model, tok = FastLanguageModel.from_pretrained('m')

# A different package whose name merely starts the same way: a prefix match
# without a word boundary would claim unsloth here.
# airom-ok: unsloth/import
from unslothx import u

# airom-ok: unsloth/construct
label = "guide = 'unsloth finetuning'"
