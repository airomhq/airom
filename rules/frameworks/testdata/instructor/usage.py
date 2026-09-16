"""instructor (structured LLM outputs) usage fixture — positive and negative cases."""
import instructor  # airom: instructor/import

# airom: instructor/patch
client = instructor.from_openai(OpenAI())

# airom-ok: instructor/import
note = "instructor library docs"

# airom-ok: instructor/patch
label = "instructor.from_openai example"
