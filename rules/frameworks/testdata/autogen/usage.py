"""AutoGen usage fixture — positive and negative cases."""
import autogen  # airom: autogen/import
from autogen import AssistantAgent, UserProxyAgent  # airom: autogen/import

# airom: autogen/agent
assistant = AssistantAgent(name="assistant")
user = UserProxyAgent(name="user")  # airom: autogen/agent

# airom-ok: autogen/import
note = "autogen release notes"

# airom-ok: autogen/agent
doc = "AssistantAgent reference"
