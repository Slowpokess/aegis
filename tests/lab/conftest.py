from collections.abc import AsyncIterator

import httpx
import pytest_asyncio

from lab.vulnerable_api.main import create_lab_app


@pytest_asyncio.fixture
async def lab_client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_lab_app())
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://lab",
        follow_redirects=False,
    ) as client:
        yield client
