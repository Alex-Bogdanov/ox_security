from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from intelligence_scanner.settings import Settings
from pymongo.asynchronous.client_session import AsyncClientSession
from .schemas import Collections


@asynccontextmanager
async def mongo_database(settings: Settings) -> AsyncIterator[AsyncIOMotorDatabase]:
    client: AsyncIOMotorClient = AsyncIOMotorClient(
        settings.mongo_uri,
        tz_aware=True,
        tzinfo=UTC,
    )

    try:
        database = client[settings.mongo_db]
        await database.command("ping")
        yield database
    finally:
        client.close()


async def ensure_indexes(database: AsyncIOMotorDatabase) -> None:
    await database[Collections.packages].create_index("name", unique=True)
    await database[Collections.packages].create_index("latest_version")
    await database[Collections.packages].create_index("scheduled_version")
    await database[Collections.packages].create_index("scheduled_scan_job_id")
    await database[Collections.packages].create_index("updated_at")

    await database[Collections.scan_jobs].create_index("package_name")
    await database[Collections.scan_jobs].create_index("version")
    await database[Collections.scan_jobs].create_index("status")
    await database[Collections.scan_jobs].create_index("queued_at")
    await database[Collections.scan_jobs].create_index("published_at")
    await database[Collections.scan_jobs].create_index("updated_at")
    await database[Collections.scan_jobs].create_index(
        [
            ("package_name", 1),
            ("version", 1),
        ],
        unique=True,
    )

    await database[Collections.package_versions].create_index("name")
    await database[Collections.package_versions].create_index("version")
    await database[Collections.package_versions].create_index("published_at")
    await database[Collections.package_versions].create_index(
        [
            ("name", 1),
            ("version", 1),
        ],
        unique=True,
    )

    await database[Collections.scan_results].create_index("name")
    await database[Collections.scan_results].create_index("version")
    await database[Collections.scan_results].create_index("score")
    await database[Collections.scan_results].create_index("risk_level")
    await database[Collections.scan_results].create_index("categories")
    await database[Collections.scan_results].create_index("created_at")
    await database[Collections.scan_results].create_index(
        [
            ("name", 1),
            ("version", 1),
        ],
        unique=True,
    )
