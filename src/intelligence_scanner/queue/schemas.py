from datetime import UTC, datetime

from pydantic import BaseModel, Field

from intelligence_scanner.enums import ScanReasonEnum


class ScanJob(BaseModel):
    job_id: str
    package_name: str
    version: str
    reason: ScanReasonEnum
    previous_version: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
