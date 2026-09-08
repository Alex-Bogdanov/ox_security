from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from intelligence_scanner.db.repositories import (
    PackageRepository,
    PackageVersionRepository,
    ScanJobRepository,
    ScanResultRepository,
)
from intelligence_scanner.enums import FindingCategoryEnum, RiskLevelEnum


class ScannerWorkerRepository:

    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        self._packages = PackageRepository(database)
        self._scan_jobs = ScanJobRepository(database)
        self._package_versions = PackageVersionRepository(database)
        self._scan_results = ScanResultRepository(database)

    async def try_mark_processing(self, job_id: str) -> dict[str, Any] | None:
        return await self._scan_jobs.try_mark_processing(job_id)

    async def get_job_status(self, job_id: str) -> str | None:
        return await self._scan_jobs.get_job_status(job_id)

    async def mark_job_completed(self, job_id: str) -> None:
        await self._scan_jobs.mark_completed(job_id)

    async def mark_job_failed(self, job_id: str, error: str) -> None:
        await self._scan_jobs.mark_failed(job_id, error)

    async def persist_successful_scan(
        self,
        package_name: str,
        version: str,
        previous_version: str | None,
        scan_job_id: str,
        score: int,
        risk_level: RiskLevelEnum,
        categories: list[FindingCategoryEnum],
        package_version_document: dict[str, Any],
        scan_result_document: dict[str, Any],
    ) -> None:
        await self._package_versions.upsert_package_version(package_version_document)
        await self._scan_results.upsert_scan_result(scan_result_document)
        await self._packages.mark_scan_completed(
            package_name,
            version,
            previous_version,
            scan_job_id,
            score,
            risk_level,
            categories,
        )
