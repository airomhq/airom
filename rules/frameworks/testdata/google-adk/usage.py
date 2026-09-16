"""Google ADK (Agent Development Kit) usage fixture — positive and negative cases."""
from google.adk.agents import LlmAgent  # airom: google-adk/import

# airom: google-adk/construct
root = SequentialAgent(name="pipeline", sub_agents=[])

# airom-ok: google-adk/import
note = "google.adk quickstart"

# airom-ok: google-adk/construct
label = "SequentialAgent design doc"
