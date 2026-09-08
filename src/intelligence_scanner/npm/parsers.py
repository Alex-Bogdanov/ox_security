import re
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any

from intelligence_scanner.enums import PackageSourceTypeEnum


class PackageNamesParser(ABC):

    @abstractmethod
    async def parse(self, payload: Any) -> list[str]:
        pass


class JsonPackageNamesParser(PackageNamesParser):

    async def parse(self, payload: Any) -> list[str]:
        if isinstance(payload, list):
            return self._extract_package_names_from_list(payload)

        if isinstance(payload, dict):
            packages = payload.get("packages") or payload.get("data") or payload.get("items")

            if isinstance(packages, list):
                return self._extract_package_names_from_list(packages)

        return []

    @staticmethod
    def _extract_package_names_from_list(items: list[Any]) -> list[str]:
        package_names: list[str] = []

        for item in items:
            if isinstance(item, str):
                package_names.append(item)
                continue

            if isinstance(item, dict):
                name = item.get("name") or item.get("package") or item.get("package_name")

                if isinstance(name, str):
                    package_names.append(name)

        return package_names


class PlainTextPackageNamesParser(PackageNamesParser):

    async def parse(self, payload: AsyncIterator[str]) -> list[str]:
        package_names: list[str] = []

        async for raw_line in payload:
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            if line.startswith("*"):
                continue

            if "," in line:
                line = line.split(",", maxsplit=1)[0].strip()

            if line:
                package_names.append(line)

        return package_names


class MeyondReadmePackageNamesParser(PackageNamesParser):
    _README_LINE_RE = re.compile(
        r"^\s*\d+\.\s+\[(?P<name>@?[a-zA-Z0-9._~/-]+)]"
        r"\(https?://(?:www\.)?npmjs\.(?:org|com)/package/[^)]+\)"
        r"\s+-\s+\d+\s*$"
    )

    async def parse(self, payload: AsyncIterator[str]) -> list[str]:
        package_names: list[str] = []

        async for raw_line in payload:
            match = self._README_LINE_RE.match(raw_line)

            if match is None:
                continue

            package_names.append(match.group("name"))

        return package_names


class PackageNamesParserFactory:

    @staticmethod
    def create(source_type: PackageSourceTypeEnum, content_type: str) -> PackageNamesParser:
        normalized_content_type = content_type.lower()

        if "text/plain" in normalized_content_type or "text/markdown" in normalized_content_type:
            if source_type == PackageSourceTypeEnum.MEYOND_README:
                return MeyondReadmePackageNamesParser()

            if source_type == PackageSourceTypeEnum.PLAIN_TEXT:
                return PlainTextPackageNamesParser()
        elif "application/json" in normalized_content_type:
            if source_type == PackageSourceTypeEnum.JSON:
                return JsonPackageNamesParser()

        raise NotImplementedError(
            f"Unsupported package source parser: source_type={source_type!r}, "
            f"content_type={content_type!r}"
        )
