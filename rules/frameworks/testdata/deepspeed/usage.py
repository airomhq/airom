"""deepspeed usage fixture — positive and negative cases."""
import deepspeed  # airom: deepspeed/import

# airom: deepspeed/construct
engine, opt, _, _ = deepspeed.initialize(model=m, config=c)

# A different package whose name merely starts the same way: a prefix match
# without a word boundary would claim deepspeed here.
# airom-ok: deepspeed/import
from deepspeedx import t

# airom-ok: deepspeed/construct
label = "paper = 'deepspeed zero stage 3'"
