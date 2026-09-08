from datetime import datetime, timedelta
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from intelligence_scanner.db.repositories import PackageRepository, ScanJobRepository, \
    ensure_aware_utc
from intelligence_scanner.db.schemas import ScanJobStatus
from intelligence_scanner.enums import ScanReasonEnum


class SchedulerRepository:
    _PUBLISHABLE_STATUSES = {
        ScanJobStatus.CREATED,
        ScanJobStatus.PUBLISH_FAILED,
    }

    _NON_PUBLISHABLE_STATUSES = {
        ScanJobStatus.QUEUED,
        ScanJobStatus.PROCESSING,
        ScanJobStatus.COMPLETED,
        ScanJobStatus.FAILED,
    }

    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        self._packages = PackageRepository(database)
        self._scan_jobs = ScanJobRepository(database)

    async def get_package_tracking_state(self, package_name: str) -> dict[str, Any] | None:
        return await self._packages.get_tracking_state(package_name)

    async def create_or_get_scan_job(
        self,
        package_name: str,
        version: str,
        reason: ScanReasonEnum,
        previous_version: str | None,
    ) -> dict[str, Any]:
        return await self._scan_jobs.create_or_get_scan_job(
            package_name,
            version,
            reason,
            previous_version,
        )

    def should_publish(
        self,
        scan_job_document: dict[str, Any],
        queued_visibility_timeout: int,
    ) -> bool:
        status = ScanJobStatus(scan_job_document["status"])

        if status in self._PUBLISHABLE_STATUSES:
            return True

        if status != ScanJobStatus.QUEUED:
            return False

        queued_at = scan_job_document.get("queued_at")
        if not isinstance(queued_at, datetime):
            return True

        queued_at = ensure_aware_utc(queued_at)
        stale_before = datetime.now(UTC) - timedelta(seconds=queued_visibility_timeout)

        return queued_at < stale_before

    async def prepare_for_publish(
        self,
        scan_job_id: str,
        queued_visibility_timeout: int,
    ) -> dict[str, Any] | None:
        return await self._scan_jobs.prepare_for_publish(scan_job_id, queued_visibility_timeout)

    async def mark_publish_failed(self, scan_job_id: str, error: str) -> None:
        await self._scan_jobs.mark_publish_failed(scan_job_id, error)

    async def update_scheduled_package_scan(
        self,
        package_name: str,
        scheduled_version: str,
        scheduled_scan_job_id: str,
        npm_dist_tags: dict[str, Any],
    ) -> None:
        await self._packages.update_scheduled_scan(
            package_name,
            scheduled_version,
            scheduled_scan_job_id,
            npm_dist_tags,
        )
