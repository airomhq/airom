"""letta usage fixture — positive and negative cases."""
from letta import create_client  # airom: letta/import

# airom: letta/construct
client = LettaClient(base_url='http://localhost')

# A different package whose name merely starts the same way: a prefix match
# without a word boundary would claim letta here.
# airom-ok: letta/import
from lettax import v

# airom-ok: letta/construct
label = "post = 'letta memory tiers'"
