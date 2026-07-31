"""camel usage fixture — positive and negative cases."""
from camel.agents import ChatAgent  # airom: camel/import

# airom: camel/construct
society = RolePlaying(task_prompt='build')

# A different package whose name merely starts the same way: a prefix match
# without a word boundary would claim camel here.
# airom-ok: camel/import
from camelot import read_pdf

# airom-ok: camel/construct
label = "case = 'camelCase naming'"
