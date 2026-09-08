import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from intelligence_scanner.db.mongo import ensure_indexes, mongo_database
from intelligence_scanner.db.repositories import (
    PackageRepository,
    PackageVersionRepository,
    ScanJobRepository,
    ScanResultRepository,
)
from intelligence_scanner.npm.client import NpmRegistryClient
from intelligence_scanner.npm.helpers import (
    get_dependencies,
    get_dist_info,
    get_package_json_subset,
    get_published_at,
    get_scripts,
    get_version_metadata,
)
from intelligence_scanner.queue.rabbit import RabbitConsumer
from intelligence_scanner.queue.schemas import ScanJob
from intelligence_scanner.services.scanner.analyzer import PackageAnalyzer
from intelligence_scanner.services.scanner.repositories import ScannerWorkerRepository
from intelligence_scanner.settings import get_settings

logger = logging.getLogger(__name__)


class ScannerWorkerService:

    def __init__(
        self,
        database: AsyncIOMotorDatabase,
        npm_client: NpmRegistryClient,
        analyzer: PackageAnalyzer,
        max_tarball_bytes: int,
    ) -> None:
        self._npm_client = npm_client
        self._analyzer = analyzer
        self._max_tarball_bytes = max_tarball_bytes

        self._repository = ScannerWorkerRepository(database)

    async def handle_job(self, job: ScanJob) -> None:
        logger.info(
            "Received scan job: job_id=%s package=%s version=%s",
            job.job_id,
            job.package_name,
            job.version,
        )

        claimed_job = await self._repository.try_mark_processing(job.job_id)
        if claimed_job is None:
            current_status = await self._repository.get_job_status(job.job_id)

            logger.info(
                "Skipping scan job because it is not claimable: job_id=%s current_status=%s",
                job.job_id,
                current_status,
            )

            return

        try:
            await self._process_claimed_job(job)
        except Exception as exc:
            logger.exception(
                "Scan job failed: job_id=%s package=%s version=%s",
                job.job_id,
                job.package_name,
                job.version,
                exc_info=exc,
            )

            await self._repository.mark_job_failed(job.job_id, str(exc))

            return

        await self._repository.mark_job_completed(job.job_id)

        logger.info(
            "Scan job completed: job_id=%s package=%s version=%s",
            job.job_id,
            job.package_name,
            job.version,
        )

    async def _process_claimed_job(self, job: ScanJob) -> None:
        metadata = await self._npm_client.fetch_package_metadata(job.package_name)

        current_version_metadata = get_version_metadata(metadata, job.version)

        if current_version_metadata is None:
            raise ValueError(
                f"Version metadata not found: package={job.package_name} version={job.version}"
            )

        previous_version_metadata = None
        if job.previous_version is not None:
            previous_version_metadata = get_version_metadata(metadata, job.previous_version)

        current_dist = get_dist_info(current_version_metadata)
        tarball_url = current_dist.get("tarball")

        if not isinstance(tarball_url, str) or not tarball_url:
            raise ValueError(
                f"Tarball URL is missing: package={job.package_name} version={job.version}"
            )

        tarball_bytes = await self._npm_client.download_bytes(
            tarball_url,
            self._max_tarball_bytes,
        )

        analysis_res = await self._analyzer.analyze(
            current_version_metadata,
            previous_version_metadata,
            tarball_bytes,
        )

        now = datetime.now(UTC)
        package_version_document = self._build_package_version_document(
            job.package_name,
            job.version,
            metadata,
            current_version_metadata,
            now,
        )

        scan_result_document = {
            "_id": f"{job.package_name}@{job.version}",
            "scan_job_id": job.job_id,
            "name": job.package_name,
            "version": job.version,
            "previous_version": job.previous_version,
            "score": analysis_res.score,
            "risk_level": analysis_res.risk_level.value,
            "categories": [category.value for category in analysis_res.categories],
            "findings": [
                finding.model_dump(mode="json")
                for finding in analysis_res.findings
            ],
            "size": analysis_res.size.model_dump(mode="json"),
            "binaries": [
                binary.model_dump(mode="json")
                for binary in analysis_res.binaries
            ],
            "command_execution_files": [
                signal.model_dump(mode="json")
                for signal in analysis_res.command_execution_files
            ],
            "shell_command_files": [
                signal.model_dump(mode="json")
                for signal in analysis_res.shell_command_files
            ],
            "obfuscated_files": [
                signal.model_dump(mode="json")
                for signal in analysis_res.obfuscated_files
            ],
            "updated_at": now,
        }

        # TODO: Without Mongo transactions, a crash between these writes can create partial
        #  persistence. For this assignment, this is acceptable if explained in README.
        #  The structure is clean enough to later wrap this in a Mongo session/transaction if
        #  MongoDB is configured as a replica set.
        await self._repository.persist_successful_scan(
            job.package_name,
            job.version,
            job.previous_version,
            job.job_id,
            analysis_res.score,
            analysis_res.risk_level,
            analysis_res.categories,
            package_version_document,
            scan_result_document,
        )

    @staticmethod
    def _build_package_version_document(
        package_name: str,
        version: str,
        package_metadata: dict[str, Any],
        version_metadata: dict[str, Any],
        updated_at: datetime,
    ) -> dict[str, Any]:
        dist = get_dist_info(version_metadata)

        return {
            "_id": f"{package_name}@{version}",
            "name": package_name,
            "version": version,
            "published_at": get_published_at(package_metadata, version),
            "tarball_url": dist.get("tarball"),
            "integrity": dist.get("integrity"),
            "shasum": dist.get("shasum"),
            "unpacked_size_bytes": dist.get("unpackedSize"),
            "file_count": dist.get("fileCount"),
            "package_json": get_package_json_subset(version_metadata),
            "dependencies": get_dependencies(version_metadata),
            "scripts": get_scripts(version_metadata),
            "maintainers": version_metadata.get("maintainers", []),
            "repository": version_metadata.get("repository"),
            "license": version_metadata.get("license"),
            "updated_at": updated_at,
        }


async def run_worker_forever() -> None:
    settings = get_settings()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    logger.info("Starting scanner worker service")

    async with mongo_database(settings) as database:
        await ensure_indexes(database)

        npm_client = NpmRegistryClient(
            settings.npm_registry_url,
            settings.worker_http_timeout_seconds,
        )

        analyzer = PackageAnalyzer(
            settings.scanner_max_files,
            settings.scanner_max_file_read_bytes,
        )

        consumer = RabbitConsumer(
            settings.rabbitmq_url,
            settings.scan_queue_name,
            settings.worker_prefetch_count,
        )

        worker = ScannerWorkerService(
            database,
            npm_client,
            analyzer,
            settings.scanner_max_tarball_bytes,
        )

        try:
            await consumer.connect()
            await consumer.consume(worker.handle_job)
        finally:
            await consumer.close()
            await npm_client.close()


def main() -> None:
    asyncio.run(run_worker_forever())


if __name__ == "__main__":
    main()