"""metagpt usage fixture — positive and negative cases."""
from metagpt.roles import Engineer  # airom: metagpt/import

# airom: metagpt/construct
company = Team()

# A different package whose name merely starts the same way: a prefix match
# without a word boundary would claim metagpt here.
# airom-ok: metagpt/import
from metagptx import w

# airom-ok: metagpt/construct
label = "blog = 'MetaGPT walkthrough'"
