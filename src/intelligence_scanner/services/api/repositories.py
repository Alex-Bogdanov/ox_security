from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from intelligence_scanner.db.schemas import Collections, ScanJobStatus
from intelligence_scanner.enums import FindingCategoryEnum, RiskLevelEnum


class ApiReadRepository:

    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        self._database = database

    async def list_packages(
        self,
        limit: int,
        offset: int,
        name: str | None = None,
        min_score: int | None = None,
        risk_level: RiskLevelEnum | None = None,
        category: FindingCategoryEnum | None = None,
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {}

        if name:
            query["name"] = {"$regex": name, "$options": "i"}

        if min_score is not None:
            query["latest_score"] = {"$gte": min_score}

        if risk_level is not None:
            query["latest_risk_level"] = risk_level.value

        if category is not None:
            query["latest_categories"] = category.value

        cursor = (
            self._database[Collections.packages]
            .find(query)
            .sort("updated_at", -1)
            .skip(offset)
            .limit(limit)
        )

        return await cursor.to_list(length=limit)

    async def get_package(self, name: str) -> dict[str, Any] | None:
        return await self._database[Collections.packages].find_one({"name": name})

    async def list_scan_jobs(
        self,
        limit: int,
        offset: int,
        package_name: str | None = None,
        status: ScanJobStatus | None = None,
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {}

        if package_name is not None:
            query["package_name"] = package_name

        if status is not None:
            query["status"] = status.value

        cursor = (
            self._database[Collections.scan_jobs]
            .find(query)
            .sort("updated_at", -1)
            .skip(offset)
            .limit(limit)
        )

        return await cursor.to_list(length=limit)

    async def get_scan_job(self, job_id: str) -> dict[str, Any] | None:
        return await self._database[Collections.scan_jobs].find_one({"_id": job_id})

    async def list_scan_results(
        self,
        limit: int,
        offset: int,
        package_name: str | None = None,
        min_score: int | None = None,
        risk_level: RiskLevelEnum | None = None,
        category: FindingCategoryEnum | None = None,
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {}

        if package_name is not None:
            query["name"] = package_name

        if min_score is not None:
            query["score"] = {"$gte": min_score}

        if risk_level is not None:
            query["risk_level"] = risk_level.value

        if category is not None:
            query["categories"] = category.value

        cursor = (
            self._database[Collections.scan_results]
            .find(query)
            .sort("updated_at", -1)
            .skip(offset)
            .limit(limit)
        )

        return await cursor.to_list(length=limit)

    async def get_scan_result(
        self,
        package_name: str,
        version: str,
    ) -> dict[str, Any] | None:
        return await self._database[Collections.scan_results].find_one(
            {
                "name": package_name,
                "version": version,
            },
        )

    async def list_package_versions(
        self,
        package_name: str,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        cursor = (
            self._database[Collections.package_versions]
            .find({"name": package_name})
            .sort("published_at", -1)
            .skip(offset)
            .limit(limit)
        )

        return await cursor.to_list(length=limit)

    async def get_package_version(
        self,
        package_name: str,
        version: str,
    ) -> dict[str, Any] | None:
        return await self._database[Collections.package_versions].find_one(
            {
                "name": package_name,
                "version": version,
            },
        )
