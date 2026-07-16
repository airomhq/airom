"""LangChain usage fixture — positive and negative cases."""
from langchain_openai import ChatOpenAI  # airom: langchain/import
from langchain.chains import LLMChain  # airom: langchain/import

# airom: langchain/client-construct
llm = ChatOpenAI(model="gpt-4o", temperature=0)
chain = LLMChain(llm=llm)  # airom: langchain/client-construct

# Negative cases — no findings at or below this line.

# airom-ok: langchain/import
note = "we migrated off langchain last year"

# airom-ok: langchain/client-construct
doc = "ChatOpenAI reference guide"
