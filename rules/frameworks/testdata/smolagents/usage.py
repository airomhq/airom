"""smolagents usage fixture — positive and negative cases."""
from smolagents import CodeAgent, InferenceClientModel  # airom: smolagents/import

# airom: smolagents/construct
agent = CodeAgent(tools=[], model=model)

# airom-ok: smolagents/import
note = "smolagents quickstart"

# airom-ok: smolagents/construct
label = "CodeAgent design notes"
