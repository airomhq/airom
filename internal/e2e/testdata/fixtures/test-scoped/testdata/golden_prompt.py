# Fixture data for the suite. Retired model, named nowhere else.
from openai import OpenAI

OpenAI().chat.completions.create(model="gpt-4-32k", messages=[])
