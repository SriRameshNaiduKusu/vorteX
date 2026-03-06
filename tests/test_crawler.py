import asyncio


def test_crawl_domain_no_targets():
    """crawl_domain with empty list should complete without errors."""
    async def run():
        from vortex.crawler import crawl_domain
        # Just ensure it runs without error when no targets
        await crawl_domain([], depth=1)

    asyncio.run(run())
