import asyncio
import logging

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

from intelligence_scanner.db.mongo import ensure_indexes, mongo_database
from intelligence_scanner.db.repositories import ScanJobRepository
from intelligence_scanner.enums import ScanReasonEnum
from intelligence_scanner.npm.client import NpmRegistryClient
from intelligence_scanner.npm.helpers import get_latest_version
from intelligence_scanner.npm.source import PackageDataSourceProtocol, PackagesDataSource
from intelligence_scanner.queue.rabbit import RabbitPublisher
from intelligence_scanner.queue.schemas import ScanJob
from intelligence_scanner.services.scheduler.repositories import SchedulerRepository
from intelligence_scanner.settings import get_settings

logger = logging.getLogger(__name__)


class SchedulerService:

    def __init__(
        self,
        database: AsyncIOMotorDatabase,
        packages_data_source: PackageDataSourceProtocol,
        publisher: RabbitPublisher,
        queued_job_visibility_timeout: int,
    ) -> None:
        self._packages_data_source = packages_data_source
        self._publisher = publisher
        self._queued_job_visibility_timeout = queued_job_visibility_timeout
        self._repository = SchedulerRepository(database)

    async def run_once(self) -> None:
        logger.info("Starting scheduler iteration")

        package_names = await self._packages_data_source.fetch_package_names()

        logger.info("Fetched %d package names", len(package_names))

        published_jobs = 0
        skipped_jobs = 0

        # TODO: optionally use asyncio.TaskGroup to publish scan jobs concurrently. But since
        #  scheduler's publishing performance is not critical, it's not worth the complexity.
        for package_name in package_names:
            try:
                result = await self._process_package(package_name)

                if result:
                    published_jobs += 1
                else:
                    skipped_jobs += 1

            except httpx.HTTPStatusError as exc:
                logger.warning(
                    "Failed to fetch package metadata for %s: status=%s",
                    package_name,
                    exc.response.status_code,
                )
            except Exception as exc:
                logger.exception(
                    "Unexpected scheduler error for package %s",
                    package_name,
                    exc_info=exc,
                )

        logger.info(
            "Finished scheduler iteration: packages=%d published_jobs=%d skipped_jobs=%d",
            len(package_names),
            published_jobs,
            skipped_jobs,
        )

    async def _process_package(self, package_name: str) -> bool:
        metadata = await self._packages_data_source.fetch_package_metadata(package_name)
        latest_registry_version = get_latest_version(metadata)

        if latest_registry_version is None:
            logger.warning("Package %s has no latest version", package_name)
            return False

        package_state = await self._repository.get_package_tracking_state(package_name)

        successfully_scanned_version = None
        scheduled_version = None

        if package_state is not None:
            successfully_scanned_version = package_state.get("latest_version")
            scheduled_version = package_state.get("scheduled_version")

        if successfully_scanned_version == latest_registry_version:
            logger.info("Package %s is up to date, skipping scan", package_name)

            return False

        reason = (
            ScanReasonEnum.NEW_PACKAGE
            if successfully_scanned_version is None
            else ScanReasonEnum.NEW_VERSION
        )

        scan_job_document = await self._repository.create_or_get_scan_job(
            package_name,
            latest_registry_version,
            reason,
            successfully_scanned_version,
        )

        scan_job_doc_id = scan_job_document["_id"]

        if not self._repository.should_publish(
            scan_job_document,
            self._queued_job_visibility_timeout,
        ):
            logger.info(
                "Skipping publish for existing scan job: job_id=%s package=%s version=%s status=%s",
                scan_job_doc_id,
                package_name,
                latest_registry_version,
                scan_job_document["status"],
            )

            return False

        prepared_job = await self._repository.prepare_for_publish(
            scan_job_doc_id,
            self._queued_job_visibility_timeout,
        )

        if prepared_job is None:
            logger.info(
                "Skipping publish because scan job was concurrently claimed or updated: job_id=%s",
                scan_job_doc_id,
            )

            return False

        job = ScanJob(
            job_id=scan_job_doc_id,
            package_name=package_name,
            version=latest_registry_version,
            reason=reason,
            previous_version=successfully_scanned_version,
        )

        try:
            await self._publisher.publish_scan_job(job)
        except Exception as exc:
            await self._repository.mark_publish_failed(scan_job_doc_id, str(exc))

            logger.exception(
                "Failed to publish scan job: job_id=%s",
                scan_job_doc_id,
                exc_info=exc,
            )

            raise

        await self._repository.update_scheduled_package_scan(
            package_name,
            latest_registry_version,
            scan_job_doc_id,
            metadata.get("dist-tags", {}),
        )

        logger.info(
            "Published scan job: job_id=%s package=%s version=%s reason=%s previous_version=%s scheduled_version_before=%s",
            scan_job_doc_id,
            package_name,
            latest_registry_version,
            reason,
            successfully_scanned_version,
            scheduled_version,
        )

        return True


async def run_scheduler_forever() -> None:
    settings = get_settings()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    logger.info("Starting scheduler service")

    async with mongo_database(settings) as database:
        await ensure_indexes(database)

        npm_client = NpmRegistryClient(
            settings.npm_registry_url,
            settings.scheduler_http_timeout_seconds,
        )

        packages_data_source = PackagesDataSource(
            npm_client,
            settings.npm_top_packages_url,
            settings.npm_top_packages_source_type,
            settings.scheduler_package_limit,
        )

        publisher = RabbitPublisher(settings.rabbitmq_url, settings.scan_queue_name)

        try:
            await publisher.connect()

            scheduler = SchedulerService(
                database,
                packages_data_source,
                publisher,
                settings.scheduler_queued_job_visibility_timeout_seconds,
            )

            while True:
                await scheduler.run_once()

                logger.info(
                    "Sleeping for %d seconds",
                    settings.scheduler_interval_seconds,
                )

                await asyncio.sleep(settings.scheduler_interval_seconds)

        finally:
            await npm_client.close()
            await publisher.close()


def main() -> None:
    asyncio.run(run_scheduler_forever())


if __name__ == "__main__":
    main()
