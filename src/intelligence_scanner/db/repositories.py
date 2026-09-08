from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from intelligence_scanner.enums import ScanReasonEnum, RiskLevelEnum, FindingCategoryEnum

from .schemas import Collections, ScanJobStatus


def ensure_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)

    return value.astimezone(UTC)


class PackageRepository:

    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        self._database = database

    async def get_tracking_state(self, package_name: str) -> dict[str, Any] | None:
        return await self._database[Collections.packages].find_one(
            {"name": package_name},
            projection={
                "latest_version": True,
                "scheduled_version": True,
                "scheduled_scan_job_id": True,
            },
        )

    async def update_scheduled_scan(
        self,
        package_name: str,
        scheduled_version: str,
        scheduled_scan_job_id: str,
        npm_dist_tags: dict[str, Any],
    ) -> None:
        now = datetime.now(UTC)

        await self._database[Collections.packages].find_one_and_update(
            {"name": package_name},
            {
                "$set": {
                    "name": package_name,
                    "scheduled_version": scheduled_version,
                    "scheduled_scan_job_id": scheduled_scan_job_id,
                    "npm_dist_tags": npm_dist_tags,
                    "updated_at": now,
                },
                "$setOnInsert": {
                    "latest_version": None,
                    "previous_version": None,
                    "latest_scan_job_id": None,
                    "latest_score": None,
                    "latest_risk_level": None,
                    "latest_categories": [],
                    "created_at": now,
                },
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )

    async def mark_scan_completed(
        self,
        package_name: str,
        version: str,
        previous_version: str | None,
        scan_job_id: str,
        score: int,
        risk_level: str | RiskLevelEnum,
        categories: list[str | FindingCategoryEnum],
    ) -> None:
        now = datetime.now(UTC)

        await self._database[Collections.packages].find_one_and_update(
            {"name": package_name},
            {
                "$set": {
                    "name": package_name,
                    "latest_version": version,
                    "previous_version": previous_version,
                    "latest_scan_job_id": scan_job_id,
                    "latest_score": score,
                    "latest_risk_level": risk_level,
                    "latest_categories": categories,
                    "scheduled_version": None,
                    "scheduled_scan_job_id": None,
                    "updated_at": now,
                },
                "$setOnInsert": {
                    "created_at": now,
                },
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )


class ScanJobRepository:

    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        self._database = database

    async def create_or_get_scan_job(
        self,
        package_name: str,
        version: str,
        reason: str | ScanReasonEnum,
        previous_version: str | None,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)

        document = {
            "_id": str(uuid4()),
            "package_name": package_name,
            "version": version,
            "reason": reason,
            "previous_version": previous_version,
            "status": ScanJobStatus.CREATED.value,
            "attempts": 0,
            "error": None,
            "published_at": None,
            "queued_at": None,
            "started_at": None,
            "finished_at": None,
            "created_at": now,
            "updated_at": now,
        }

        try:
            await self._database[Collections.scan_jobs].insert_one(document)
            return document
        except DuplicateKeyError:
            existing = await self._database[Collections.scan_jobs].find_one(
                {
                    "package_name": package_name,
                    "version": version,
                },
            )

            if existing is None:
                raise

            return existing

    async def prepare_for_publish(
        self,
        job_id: str,
        queued_visibility_timeout: int,
    ) -> dict[str, Any] | None:
        now = datetime.now(UTC)
        stale_before = now - timedelta(seconds=queued_visibility_timeout)

        return await self._database[Collections.scan_jobs].find_one_and_update(
            {
                "_id": job_id,
                "$or": [
                    {
                        "status": ScanJobStatus.CREATED.value,
                    },
                    {
                        "status": ScanJobStatus.PUBLISH_FAILED.value,
                    },
                    {
                        "status": ScanJobStatus.QUEUED.value,
                        "$or": [
                            {"queued_at": None},
                            {"queued_at": {"$lt": stale_before}},
                        ],
                    },
                ],
            },
            {
                "$set": {
                    "status": ScanJobStatus.QUEUED.value,
                    "queued_at": now,
                    "published_at": now,
                    "error": None,
                    "updated_at": now,
                },
            },
            return_document=ReturnDocument.AFTER,
        )

    async def mark_publish_failed(self, job_id: str, error: str) -> None:
        now = datetime.now(UTC)

        await self._database[Collections.scan_jobs].update_one(
            {
                "_id": job_id,
                "status": {
                    "$in": [
                        ScanJobStatus.CREATED.value,
                        ScanJobStatus.PUBLISH_FAILED.value,
                        ScanJobStatus.QUEUED.value,
                    ],
                },
            },
            {
                "$set": {
                    "status": ScanJobStatus.PUBLISH_FAILED.value,
                    "error": error,
                    "updated_at": now,
                },
            },
        )

    async def try_mark_processing(self, job_id: str) -> dict[str, Any] | None:
        now = datetime.now(UTC)

        return await self._database[Collections.scan_jobs].find_one_and_update(
            {
                "_id": job_id,
                "status": ScanJobStatus.QUEUED.value,
            },
            {
                "$set": {
                    "status": ScanJobStatus.PROCESSING.value,
                    "started_at": now,
                    "updated_at": now,
                    "error": None,
                },
                "$inc": {
                    "attempts": 1,
                },
            },
            return_document=ReturnDocument.AFTER,
        )

    async def get_job_status(self, job_id: str) -> str | None:
        document = await self._database[Collections.scan_jobs].find_one(
            {"_id": job_id},
            projection={"status": True},
        )

        if document is None:
            return None

        status = document.get("status")
        return status if isinstance(status, str) else None

    async def mark_completed(self, job_id: str) -> None:
        now = datetime.now(UTC)

        await self._database[Collections.scan_jobs].update_one(
            {
                "_id": job_id,
                "status": ScanJobStatus.PROCESSING.value,
            },
            {
                "$set": {
                    "status": ScanJobStatus.COMPLETED.value,
                    "finished_at": now,
                    "updated_at": now,
                    "error": None,
                },
            },
        )

    async def mark_failed(self, job_id: str, error: str) -> None:
        now = datetime.now(UTC)

        await self._database[Collections.scan_jobs].update_one(
            {
                "_id": job_id,
                "status": ScanJobStatus.PROCESSING.value,
            },
            {
                "$set": {
                    "status": ScanJobStatus.FAILED.value,
                    "finished_at": now,
                    "updated_at": now,
                    "error": error,
                },
            },
        )


class PackageVersionRepository:

    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        self._database = database

    async def upsert_package_version(self, document: dict[str, Any]) -> None:
        await self._database[Collections.package_versions].update_one(
            {"_id": document["_id"]},
            {
                "$set": document,
                "$setOnInsert": {
                    "created_at": document["updated_at"],
                },
            },
            upsert=True,
        )


class ScanResultRepository:

    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        self._database = database

    async def upsert_scan_result(self, document: dict[str, Any]) -> None:
        await self._database[Collections.scan_results].update_one(
            {"_id": document["_id"]},
            {
                "$set": document,
                "$setOnInsert": {
                    "created_at": document["updated_at"],
                },
            },
            upsert=True,
        )
