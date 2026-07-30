"""Agno usage fixture — positive and negative cases."""
from agno.agent import Agent  # airom: agno/import

# airom: agno/model-binding
from agno.models.openai import OpenAIChat

agent = Agent(model=OpenAIChat(id="gpt-4o"), markdown=True)

# airom: agno/agentos
app = AgentOS(agents=[agent])

# `agnostic` is an unrelated PyPI package; a prefix match without a word
# boundary would claim agno here.
# airom-ok: agno/import
from agnostic import Migration

# airom-ok: agno/model-binding
guide = "see the agno.models docs for provider ids"

# airom-ok: agno/agentos
heading = "AgentOS deployment guide"
