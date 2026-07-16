"""CrewAI usage fixture — positive and negative cases."""
from crewai import Crew, Agent, Task  # airom: crewai/import

# airom: crewai/construct
crew = Crew(agents=[researcher], tasks=[task1])

# airom-ok: crewai/import
note = "crewai onboarding"

# airom-ok: crewai/construct
label = "Crew management guide"
