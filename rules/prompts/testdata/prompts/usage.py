"""Prompt-usage fixture — positive and negative cases."""
from langchain.prompts import PromptTemplate, ChatPromptTemplate
from langchain.schema import SystemMessage

# airom: prompts/langchain-template
tmpl = PromptTemplate.from_template("Answer: {question}")
chat = ChatPromptTemplate.from_messages([("system", "You are helpful")])  # airom: prompts/langchain-template

# airom: prompts/system-message
system_prompt = "You are a careful assistant."
msg = SystemMessage(content="Be concise")  # airom: prompts/system-message

# airom: prompts/jinja-var
user_prompt = "Hello {{ name }}, welcome"

# airom-ok: prompts/langchain-template
note = "PromptTemplate is a class"

# airom-ok: prompts/system-message
doc = "system_prompt best practices"

# airom-ok: prompts/jinja-var
greeting = "Hello {name}, welcome"
