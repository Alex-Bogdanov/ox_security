from typing import Any, Protocol

from pydantic import AnyUrl

from intelligence_scanner.enums import PackageSourceTypeEnum

from .client import NpmRegistryClient
from .parsers import JsonPackageNamesParser, PackageNamesParserFactory


class PackageDataSourceProtocol(Protocol):

    async def fetch_package_names(self) -> list[str]:
        raise NotImplementedError

    async def fetch_package_metadata(self, package_name: str) -> dict[str, Any]:
        raise NotImplementedError


class PackagesDataSource:

    def __init__(
        self,
        client: NpmRegistryClient,
        top_packages_url: AnyUrl,
        source_type: PackageSourceTypeEnum,
        limit: int,
    ) -> None:
        self._client = client
        self._top_packages_url = str(top_packages_url)
        self._source_type = source_type
        self._limit = limit

    async def fetch_package_names(self) -> list[str]:
        headers = await self._client.head(self._top_packages_url)
        content_type = headers.get("content-type", "")

        parser = PackageNamesParserFactory.create(self._source_type, content_type)

        if isinstance(parser, JsonPackageNamesParser):
            payload = await self._client.get_json(self._top_packages_url)
            package_names = await parser.parse(payload)
        else:
            async with self._client.stream_lines(self._top_packages_url) as lines:
                package_names = await parser.parse(lines)

        # keeps the original order of the packages
        unique_names = list(dict.fromkeys(package_names))
        return unique_names[:self._limit]

    async def fetch_package_metadata(self, package_name: str) -> dict[str, Any]:
        return await self._client.fetch_package_metadata(package_name)
