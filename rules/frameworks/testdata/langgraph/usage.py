"""LangGraph usage fixture — positive and negative cases."""
from langgraph.graph import StateGraph, START, END  # airom: langgraph/import

# airom: langgraph/construct
graph = StateGraph(dict)

# airom-ok: langgraph/import
note = "langgraph tutorial notes"

# airom-ok: langgraph/construct
label = "StateGraph diagram caption"
