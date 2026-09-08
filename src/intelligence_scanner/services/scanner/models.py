from functools import cached_property
from typing import Any

from pydantic import BaseModel, Field, computed_field

from intelligence_scanner.enums import (
    BinaryTypeEnum,
    FindingCategoryEnum,
    FindingSeverityEnum,
    RiskLevelEnum,
)


class Finding(BaseModel):
    category: FindingCategoryEnum
    severity: FindingSeverityEnum
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    score_impact: int


class BinaryFinding(BaseModel):
    path: str
    binary_type: BinaryTypeEnum
    size_bytes: int


class FileSignal(BaseModel):
    path: str
    category: FindingCategoryEnum
    matched_patterns: list[str] = Field(default_factory=list)


class PackageSizeDelta(BaseModel):
    current_bytes: int | None = None
    previous_bytes: int | None = None
    delta_bytes: int | None = None
    delta_percent: float | None = None


class PackageAnalysisResult(BaseModel):
    findings: list[Finding]
    size: PackageSizeDelta
    binaries: list[BinaryFinding] = Field(default_factory=list)
    command_execution_files: list[FileSignal] = Field(default_factory=list)
    shell_command_files: list[FileSignal] = Field(default_factory=list)
    obfuscated_files: list[FileSignal] = Field(default_factory=list)

    @computed_field
    @cached_property
    def score(self) -> int:
        score = sum(finding.score_impact for finding in self.findings)
        return min(max(score, 1), 100)

    @computed_field
    @cached_property
    def risk_level(self) -> RiskLevelEnum:
        if self.score <= 20:
            return RiskLevelEnum.LOW

        if self.score <= 50:
            return RiskLevelEnum.MEDIUM

        if self.score <= 80:
            return RiskLevelEnum.HIGH

        return RiskLevelEnum.CRITICAL

    @computed_field
    @cached_property
    def categories(self) -> list[FindingCategoryEnum]:
        return sorted(
            {finding.category for finding in self.findings},
            key=lambda item: item.value,
        )
