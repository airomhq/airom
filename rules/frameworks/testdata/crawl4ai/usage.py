"""Crawl4AI usage fixture — positive and negative cases."""
import asyncio
from crawl4ai import AsyncWebCrawler, BrowserConfig  # airom: crawl4ai/import


async def scrape(url: str) -> str:
    # airom: crawl4ai/crawler
    async with AsyncWebCrawler(config=BrowserConfig(headless=True)) as crawler:
        result = await crawler.arun(url=url)
        return result.markdown


# airom-ok: crawl4ai/import
note = "crawl4ai evaluation notes"

# airom-ok: crawl4ai/crawler
label = "AsyncWebCrawler configuration guide"
