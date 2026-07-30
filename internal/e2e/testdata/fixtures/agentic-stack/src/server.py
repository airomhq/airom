"""Research agent exposed as an MCP server."""

import asyncio

from agno.agent import Agent
from agno.models.openai import OpenAIChat
from crawl4ai import AsyncWebCrawler, BrowserConfig
from fastmcp import FastMCP

mcp = FastMCP("research-server")
agent = Agent(model=OpenAIChat(id="gpt-4o"), markdown=True)


@mcp.tool
async def research(url: str) -> str:
    async with AsyncWebCrawler(config=BrowserConfig(headless=True)) as crawler:
        page = await crawler.arun(url=url)
    return agent.run(page.markdown).content
