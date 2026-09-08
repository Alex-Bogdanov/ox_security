from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from intelligence_scanner.db.schemas import ScanJobStatus
from intelligence_scanner.enums import FindingCategoryEnum, RiskLevelEnum


class HealthResponse(BaseModel):
    status: str = "ok"


class PaginationParams(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class PackageListItem(BaseModel):
    name: str
    latest_version: str | None = None
    previous_version: str | None = None

    scheduled_version: str | None = None
    scheduled_scan_job_id: str | None = None

    latest_scan_job_id: str | None = None
    latest_score: int | None = None
    latest_risk_level: RiskLevelEnum | None = None
    latest_categories: list[FindingCategoryEnum] = Field(default_factory=list)

    updated_at: datetime | None = None


class PackageDetail(BaseModel):
    name: str
    latest_version: str | None = None
    previous_version: str | None = None
    npm_dist_tags: dict[str, Any] = Field(default_factory=dict)

    scheduled_version: str | None = None
    scheduled_scan_job_id: str | None = None

    latest_scan_job_id: str | None = None
    latest_score: int | None = None
    latest_risk_level: RiskLevelEnum | None = None
    latest_categories: list[FindingCategoryEnum] = Field(default_factory=list)

    created_at: datetime | None = None
    updated_at: datetime | None = None


class ScanJobResponse(BaseModel):
    id: str = Field(alias="_id")
    package_name: str
    version: str
    reason: str
    previous_version: str | None = None
    status: ScanJobStatus
    attempts: int = 0
    error: str | None = None

    published_at: datetime | None = None
    queued_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class PackageVersionResponse(BaseModel):
    id: str = Field(alias="_id")
    name: str
    version: str
    published_at: datetime | None = None

    tarball_url: str | None = None
    integrity: str | None = None
    shasum: str | None = None
    unpacked_size_bytes: int | None = None
    file_count: int | None = None

    package_json: dict[str, Any] = Field(default_factory=dict)
    dependencies: dict[str, Any] = Field(default_factory=dict)
    scripts: dict[str, Any] = Field(default_factory=dict)

    maintainers: list[Any] = Field(default_factory=list)
    repository: Any = None
    license: Any = None

    created_at: datetime | None = None
    updated_at: datetime | None = None


class ScanResultResponse(BaseModel):
    id: str = Field(alias="_id")
    scan_job_id: str
    name: str
    version: str
    previous_version: str | None = None

    score: int
    risk_level: RiskLevelEnum
    categories: list[FindingCategoryEnum] = Field(default_factory=list)

    findings: list[dict[str, Any]] = Field(default_factory=list)
    size: dict[str, Any] = Field(default_factory=dict)

    binaries: list[dict[str, Any]] = Field(default_factory=dict)
    command_execution_files: list[dict[str, Any]] = Field(default_factory=list)
    shell_command_files: list[dict[str, Any]] = Field(default_factory=list)
    obfuscated_files: list[dict[str, Any]] = Field(default_factory=list)

    created_at: datetime | None = None
    updated_at: datetime | None = None
