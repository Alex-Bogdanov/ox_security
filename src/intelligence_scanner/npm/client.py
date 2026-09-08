from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from pydantic import AnyUrl


class NpmRegistryClient:

    def __init__(self, registry_url: AnyUrl, timeout_seconds: float) -> None:
        self._registry_url = str(registry_url).rstrip("/")
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=True,
            headers={
                "User-Agent": "ox-security-intelligence-scanner/0.1.0",
                "Accept": "application/json,text/plain,*/*",
            },
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def fetch_package_metadata(self, package_name: str) -> dict[str, Any]:
        encoded_name = self._encode_package_name(package_name)
        response = await self._client.get(f"{self._registry_url}/{encoded_name}")
        response.raise_for_status()
        return response.json()

    async def download_bytes(self, url: str, max_bytes: int) -> bytes:
        chunks: list[bytes] = []
        downloaded_bytes = 0

        async with self._client.stream("GET", url) as response:
            response.raise_for_status()

            async for chunk in response.aiter_bytes():
                downloaded_bytes += len(chunk)

                if downloaded_bytes > max_bytes:
                    raise ValueError(
                        f"Downloaded payload is too large: max_bytes={max_bytes}"
                    )

                chunks.append(chunk)

        return b"".join(chunks)

    async def head(self, url: str) -> httpx.Headers:
        response = await self._client.head(url)
        response.raise_for_status()
        return response.headers

    async def get_json(self, url: str) -> Any:
        response = await self._client.get(url)
        response.raise_for_status()
        return response.json()

    async def get_text(self, url: str) -> str:
        response = await self._client.get(url)
        response.raise_for_status()
        return response.text

    @asynccontextmanager
    async def stream_lines(self, url: str) -> AsyncIterator[AsyncIterator[str]]:
        async with self._client.stream("GET", url) as response:
            response.raise_for_status()
            yield response.aiter_lines()

    @staticmethod
    def _encode_package_name(package_name: str) -> str:
        if package_name.startswith("@"):
            return package_name.replace("/", "%2F", 1)

        return package_name
