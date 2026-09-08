import asyncio
from enum import StrEnum
from typing import Any

from intelligence_scanner.enums import FindingCategoryEnum, FindingSeverityEnum
from intelligence_scanner.npm.helpers import get_package_size, get_scripts

from .models import (
    Finding,
    PackageAnalysisResult,
    PackageSizeDelta,
)
from .tarball import scan_tarball_bytes


class InstallHooksEnum(StrEnum):
    PREINSTALL = "preinstall"
    INSTALL = "install"
    POSTINSTALL = "postinstall"


class PackageAnalyzer:
    def __init__(
        self,
        max_files: int,
        max_file_read_bytes: int,
    ) -> None:
        self._max_files = max_files
        self._max_file_read_bytes = max_file_read_bytes

    async def analyze(
        self,
        current_version_metadata: dict[str, Any],
        previous_version_metadata: dict[str, Any] | None,
        tarball_bytes: bytes,
    ) -> PackageAnalysisResult:
        tarball_result = await asyncio.to_thread(
            scan_tarball_bytes,
            tarball_bytes,
            self._max_files,
            self._max_file_read_bytes,
        )

        findings: list[Finding] = []

        size_delta = self._analyze_size_delta(
            current_version_metadata=current_version_metadata,
            previous_version_metadata=previous_version_metadata,
        )
        findings.extend(self._size_findings(size_delta))

        findings.extend(
            self._install_hook_findings(
                current_version_metadata=current_version_metadata,
                previous_version_metadata=previous_version_metadata,
            )
        )

        if tarball_result.reached_file_limit:
            findings.append(
                Finding(
                    category=FindingCategoryEnum.SCAN_LIMIT_REACHED,
                    severity=FindingSeverityEnum.MEDIUM,
                    description="Tarball scan stopped because the maximum file count limit was reached",
                    evidence={
                        "file_count_scanned": tarball_result.file_count,
                    },
                    score_impact=10,
                )
            )

        if tarball_result.binaries:
            findings.append(
                Finding(
                    category=FindingCategoryEnum.BINARY_EXECUTABLE,
                    severity=FindingSeverityEnum.HIGH,
                    description="Package contains executable/native binary files",
                    evidence={
                        "count": len(tarball_result.binaries),
                        "files": [
                            binary.model_dump(mode="json")
                            for binary in tarball_result.binaries[:20]
                        ],
                    },
                    score_impact=25 + (15 if len(tarball_result.binaries) > 3 else 0),
                )
            )

        if tarball_result.command_execution_files:
            findings.append(
                Finding(
                    category=FindingCategoryEnum.COMMAND_EXECUTION,
                    severity=FindingSeverityEnum.HIGH,
                    description="Package files contain command execution indicators",
                    evidence={
                        "count": len(tarball_result.command_execution_files),
                        "files": [
                            signal.model_dump(mode="json")
                            for signal in tarball_result.command_execution_files[:20]
                        ],
                    },
                    score_impact=20,
                )
            )

        if tarball_result.shell_command_files:
            findings.append(
                Finding(
                    category=FindingCategoryEnum.SHELL_COMMAND,
                    severity=FindingSeverityEnum.LOW,
                    description="Package files contain shell command indicators",
                    evidence={
                        "count": len(tarball_result.shell_command_files),
                        "files": [
                            signal.model_dump(mode="json")
                            for signal in tarball_result.shell_command_files[:20]
                        ],
                    },
                    score_impact=15,
                )
            )

        if tarball_result.obfuscated_files:
            findings.append(
                Finding(
                    category=FindingCategoryEnum.OBFUSCATION,
                    severity=FindingSeverityEnum.MEDIUM,
                    description="Package files contain potential obfuscation indicators",
                    evidence={
                        "count": len(tarball_result.obfuscated_files),
                        "files": [
                            signal.model_dump(mode="json")
                            for signal in tarball_result.obfuscated_files[:20]
                        ],
                    },
                    score_impact=20,
                )
            )

        return PackageAnalysisResult(
            findings=findings,
            size=size_delta,
            binaries=tarball_result.binaries,
            command_execution_files=tarball_result.command_execution_files,
            shell_command_files=tarball_result.shell_command_files,
            obfuscated_files=tarball_result.obfuscated_files,
        )

    @staticmethod
    def _analyze_size_delta(
        current_version_metadata: dict[str, Any],
        previous_version_metadata: dict[str, Any] | None,
    ) -> PackageSizeDelta:
        current_size = get_package_size(current_version_metadata)

        if previous_version_metadata is None:
            return PackageSizeDelta(
                current_bytes=current_size,
                previous_bytes=None,
                delta_bytes=None,
                delta_percent=None,
            )

        previous_size = get_package_size(previous_version_metadata)

        if current_size is None or previous_size is None or previous_size == 0:
            return PackageSizeDelta(
                current_bytes=current_size,
                previous_bytes=previous_size,
                delta_bytes=None,
                delta_percent=None,
            )

        delta_bytes = current_size - previous_size
        delta_percent = (delta_bytes / previous_size) * 100

        return PackageSizeDelta(
            current_bytes=current_size,
            previous_bytes=previous_size,
            delta_bytes=delta_bytes,
            delta_percent=round(delta_percent, 2),
        )

    @staticmethod
    def _size_findings(size_delta: PackageSizeDelta) -> list[Finding]:
        if size_delta.delta_percent is None:
            return []

        abs_delta_percent = abs(size_delta.delta_percent)

        if size_delta.delta_percent > 300:
            return [
                Finding(
                    category=FindingCategoryEnum.SIZE_CHANGE,
                    severity=FindingSeverityEnum.MEDIUM,
                    description="Package size increased by more than 300%",
                    evidence=size_delta.model_dump(),
                    score_impact=20,
                )
            ]

        if size_delta.delta_percent > 100:
            return [
                Finding(
                    category=FindingCategoryEnum.SIZE_CHANGE,
                    severity=FindingSeverityEnum.MEDIUM,
                    description="Package size increased by more than 100%",
                    evidence=size_delta.model_dump(),
                    score_impact=10,
                )
            ]

        if size_delta.delta_percent > 50:
            return [
                Finding(
                    category=FindingCategoryEnum.SIZE_CHANGE,
                    severity=FindingSeverityEnum.LOW,
                    description="Package size increased by more than 50%",
                    evidence=size_delta.model_dump(),
                    score_impact=5,
                )
            ]

        if size_delta.delta_percent < 0 and abs_delta_percent > 70:
            return [
                Finding(
                    category=FindingCategoryEnum.SIZE_CHANGE,
                    severity=FindingSeverityEnum.LOW,
                    description="Package size decreased by more than 70%",
                    evidence=size_delta.model_dump(),
                    score_impact=5,
                )
            ]

        return []

    @staticmethod
    def _install_hook_findings(
        current_version_metadata: dict[str, Any],
        previous_version_metadata: dict[str, Any] | None,
    ) -> list[Finding]:
        current_scripts = get_scripts(current_version_metadata)
        previous_scripts = get_scripts(previous_version_metadata or {})

        findings: list[Finding] = []

        for hook_name in InstallHooksEnum:
            current_value = current_scripts.get(hook_name)
            previous_value = previous_scripts.get(hook_name)

            current_exists = isinstance(current_value, str) and bool(current_value.strip())
            previous_exists = isinstance(previous_value, str) and bool(previous_value.strip())

            if current_exists and not previous_exists:
                findings.append(
                    Finding(
                        category=FindingCategoryEnum.INSTALL_HOOK_ADDED,
                        severity=FindingSeverityEnum.HIGH,
                        description=f"NPM lifecycle hook was added: {hook_name}",
                        evidence={
                            "script": hook_name,
                            "current_value": current_value,
                            "previous_value": previous_value,
                        },
                        score_impact=(
                            30 if hook_name in {
                                InstallHooksEnum.PREINSTALL,
                                InstallHooksEnum.POSTINSTALL,
                            } else 25
                        ),
                    )
                )
            elif current_exists and previous_exists:
                findings.append(
                    Finding(
                        category=FindingCategoryEnum.INSTALL_HOOK_EXISTING,
                        severity=FindingSeverityEnum.MEDIUM,
                        description=f"NPM lifecycle hook exists: {hook_name}",
                        evidence={
                            "script": hook_name,
                            "current_value": current_value,
                            "previous_value": previous_value,
                        },
                        score_impact=10,
                    )
                )
            elif previous_exists and not current_exists:
                findings.append(
                    Finding(
                        category=FindingCategoryEnum.INSTALL_HOOK_REMOVED,
                        severity=FindingSeverityEnum.INFO,
                        description=f"NPM lifecycle hook was removed: {hook_name}",
                        evidence={
                            "script": hook_name,
                            "current_value": current_value,
                            "previous_value": previous_value,
                        },
                        score_impact=3,
                    )
                )

        return findings
