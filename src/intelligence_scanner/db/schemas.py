from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from intelligence_scanner.enums import (
    FindingCategoryEnum,
    ScanReasonEnum,
    RiskLevelEnum,
    FindingSeverityEnum,
)


class Collections:
    packages = "packages"
    scan_jobs = "scan_jobs"
    package_versions = "package_versions"
    scan_results = "scan_results"


class ScanJobStatus(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    PUBLISH_FAILED = "publish_failed"


class PackageDocument(BaseModel):
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

    created_at: datetime
    updated_at: datetime


class ScanJobDocument(BaseModel):
    id: str = Field(alias="_id")
    package_name: str
    version: str
    reason: ScanReasonEnum
    previous_version: str | None = None
    status: ScanJobStatus = ScanJobStatus.CREATED
    attempts: int = 0
    error: str | None = None
    published_at: datetime | None = None
    queued_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class PackageVersionDocument(BaseModel):
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
    updated_at: datetime


class ScanFindingDocument(BaseModel):
    category: FindingCategoryEnum
    severity: FindingSeverityEnum
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    score_impact: int


class ScanFileSignalDocument(BaseModel):
    path: str
    category: FindingCategoryEnum
    matched_patterns: list[str] = Field(default_factory=list)


class ScanBinaryFindingDocument(BaseModel):
    path: str
    binary_type: str
    size_bytes: int


class ScanResultDocument(BaseModel):
    id: str = Field(alias="_id")
    scan_job_id: str
    name: str
    version: str
    previous_version: str | None = None

    score: int
    risk_level: RiskLevelEnum
    categories: list[FindingCategoryEnum] = Field(default_factory=list)

    findings: list[ScanFindingDocument] = Field(default_factory=list)
    size: dict[str, Any] = Field(default_factory=dict)

    binaries: list[ScanBinaryFindingDocument] = Field(default_factory=list)
    command_execution_files: list[ScanFileSignalDocument] = Field(default_factory=list)
    shell_command_files: list[ScanFileSignalDocument] = Field(default_factory=list)
    obfuscated_files: list[ScanFileSignalDocument] = Field(default_factory=list)

    created_at: datetime | None = None
    updated_at: datetime
