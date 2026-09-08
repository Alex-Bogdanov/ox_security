from functools import lru_cache

from pydantic import AnyUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from intelligence_scanner.enums import PackageSourceTypeEnum


class Settings(BaseSettings):
    mongo_uri: str = Field(default="mongodb://localhost:27017", alias="MONGO_URI")
    mongo_db: str = Field(default="intelligence_scanner", alias="MONGO_DB")

    rabbitmq_url: str = Field(
        default="amqp://guest:guest@localhost:5672/",
        alias="RABBITMQ_URL",
    )
    scan_queue_name: str = Field(default="npm.scan.jobs", alias="SCAN_QUEUE_NAME")

    npm_registry_url: AnyUrl = Field(
        default="https://registry.npmjs.org",
        alias="NPM_REGISTRY_URL",
    )

    npm_top_packages_url: AnyUrl = Field(
        default="https://raw.githubusercontent.com/Meyond/npm-top-1000-packages/refs/heads/main/README.md",
        alias="NPM_TOP_PACKAGES_URL",
    )

    npm_top_packages_source_type: PackageSourceTypeEnum = Field(
        default=PackageSourceTypeEnum.MEYOND_README,
        alias="NPM_TOP_PACKAGES_SOURCE_TYPE",
    )

    scheduler_interval_seconds: int = Field(
        default=1800,
        alias="SCHEDULER_INTERVAL_SECONDS",
    )

    scheduler_package_limit: int = Field(
        default=1000,
        alias="SCHEDULER_PACKAGE_LIMIT",
    )

    scheduler_http_timeout_seconds: float = Field(
        default=20.0,
        alias="SCHEDULER_HTTP_TIMEOUT_SECONDS",
    )

    scheduler_queued_job_visibility_timeout_seconds: int = Field(
        default=300,
        alias="SCHEDULER_QUEUED_JOB_VISIBILITY_TIMEOUT_SECONDS",
    )

    worker_prefetch_count: int = Field(default=4, alias="WORKER_PREFETCH_COUNT")
    worker_http_timeout_seconds: float = Field(default=30.0, alias="WORKER_HTTP_TIMEOUT_SECONDS")

    scanner_max_tarball_bytes: int = Field(
        default=50 * 1024 * 1024,
        alias="SCANNER_MAX_TARBALL_BYTES",
    )
    scanner_max_files: int = Field(default=5000, alias="SCANNER_MAX_FILES")
    scanner_max_file_read_bytes: int = Field(
        default=1024 * 1024,
        alias="SCANNER_MAX_FILE_READ_BYTES",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
