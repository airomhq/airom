"""langroid usage fixture — positive and negative cases."""
import langroid as lr  # airom: langroid/import

# airom: langroid/construct
agent = ChatAgent(cfg)

# A different package whose name merely starts the same way: a prefix match
# without a word boundary would claim langroid here.
# airom-ok: langroid/import
from langroidx import q

# airom-ok: langroid/construct
label = "readme = 'langroid quickstart'"
