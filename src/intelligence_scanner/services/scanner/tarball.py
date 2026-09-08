import io
import logging
import re
import tarfile
from dataclasses import dataclass

from intelligence_scanner.enums import FindingCategoryEnum, BinaryTypeEnum

from .models import BinaryFinding, FileSignal

logger = logging.getLogger(__name__)

_TEXT_EXTENSIONS = {
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".cmd",
    ".bat",
    ".py",
    ".rb",
    ".pl",
}

_BINARY_EXTENSION_HINTS = {
    ".exe": BinaryTypeEnum.PE_EXE,
    ".dll": BinaryTypeEnum.PE_DLL,
    ".node": BinaryTypeEnum.NATIVE_NODE_ADDON,
    ".so": BinaryTypeEnum.ELF_SHARED_OBJECT,
    ".dylib": BinaryTypeEnum.MACHO_DYLIB,
}

_COMMAND_EXEC_PATTERNS = [
    r"child_process",
    r"require\([\"']child_process[\"']\)",
    r"\bexec\s*\(",
    r"\bexecSync\s*\(",
    r"\bspawn\s*\(",
    r"\bspawnSync\s*\(",
    r"\bfork\s*\(",
]

_SHELL_COMMAND_PATTERNS = [
    r"\bcurl\b",
    r"\bwget\b",
    r"\bchmod\b",
    r"\bchown\b",
    r"\bbash\b",
    r"\bsh\s+-c\b",
    r"\bpowershell\b",
    r"\bcmd\.exe\b",
    r"\bcertutil\b",
    r"\bnc\b",
    r"\bnetcat\b",
]

_OBFUSCATION_PATTERNS = [
    r"\beval\s*\(",
    r"\bFunction\s*\(",
    r"\batob\s*\(",
    r"Buffer\.from\s*\([^)]*[\"']base64[\"']",
    r"String\.fromCharCode",
    r"\bunescape\s*\(",
    r"\bdecodeURIComponent\s*\(",
    r"_0x[a-fA-F0-9]+",
    r"[A-Za-z0-9+/]{120,}={0,2}",
]


@dataclass(slots=True, frozen=True)
class TarballScanResult:
    file_count: int
    unpacked_size_bytes: int
    reached_file_limit: bool
    max_files: int
    binaries: list[BinaryFinding]
    command_execution_files: list[FileSignal]
    shell_command_files: list[FileSignal]
    obfuscated_files: list[FileSignal]


def scan_tarball_bytes(
    tarball_bytes: bytes,
    max_files: int,
    max_file_read_bytes: int,
) -> TarballScanResult:
    binaries: list[BinaryFinding] = []
    command_execution_files: list[FileSignal] = []
    shell_command_files: list[FileSignal] = []
    obfuscated_files: list[FileSignal] = []

    file_count = 0
    unpacked_size_bytes = 0
    reached_file_limit = False

    with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue

            if file_count >= max_files:
                reached_file_limit = True
                logger.warning(
                    "Tarball %s contains too many files: max_files=%s",
                    archive.name,
                    max_files,
                )

                break

            unpacked_size_bytes += max(member.size, 0)

            path = _normalize_tar_path(member.name)
            if not path:
                continue

            extracted = archive.extractfile(member)
            if extracted is None:
                continue

            sample = extracted.read(max_file_read_bytes)

            binary_type = _detect_binary_type(path, sample)
            if binary_type is not None:
                binaries.append(
                    BinaryFinding(
                        path=path,
                        binary_type=binary_type,
                        size_bytes=member.size,
                    )
                )

            if _should_scan_as_text(path, sample):
                text = _decode_text_sample(sample)

                command_matches = _match_patterns(text, _COMMAND_EXEC_PATTERNS)
                if command_matches:
                    command_execution_files.append(
                        FileSignal(
                            path=path,
                            category=FindingCategoryEnum.COMMAND_EXECUTION,
                            matched_patterns=command_matches,
                        )
                    )

                shell_cmd_matches = _match_patterns(text, _SHELL_COMMAND_PATTERNS)
                if shell_cmd_matches:
                    shell_command_files.append(
                        FileSignal(
                            path=path,
                            category=FindingCategoryEnum.SHELL_COMMAND,
                            matched_patterns=shell_cmd_matches,
                        )
                    )

                obfuscation_matches = _match_patterns(text, _OBFUSCATION_PATTERNS)
                if obfuscation_matches:
                    obfuscated_files.append(
                        FileSignal(
                            path=path,
                            category=FindingCategoryEnum.OBFUSCATION,
                            matched_patterns=obfuscation_matches,
                        )
                    )

            file_count += 1

    return TarballScanResult(
        file_count=file_count,
        unpacked_size_bytes=unpacked_size_bytes,
        reached_file_limit=reached_file_limit,
        max_files=max_files,
        binaries=binaries,
        command_execution_files=command_execution_files,
        shell_command_files=shell_command_files,
        obfuscated_files=obfuscated_files,
    )


def _normalize_tar_path(path: str) -> str | None:
    normalized = path.replace("\\", "/").lstrip("/")

    if not normalized:
        return None

    parts = normalized.split("/")

    if ".." in parts:
        return None

    return normalized


def _detect_binary_type(path: str, sample: bytes) -> BinaryTypeEnum | None:
    lower_path = path.lower()

    if sample.startswith(b"\x7fELF"):
        return BinaryTypeEnum.ELF

    if sample.startswith(b"MZ"):
        if lower_path.endswith(".dll"):
            return BinaryTypeEnum.PE_DLL

        if lower_path.endswith(".exe"):
            return BinaryTypeEnum.PE_EXE

        return BinaryTypeEnum.PE

    for extension, binary_type in _BINARY_EXTENSION_HINTS.items():
        if lower_path.endswith(extension):
            return binary_type

    return None


def _should_scan_as_text(path: str, sample: bytes) -> bool:
    lower_path = path.lower()

    if any(lower_path.endswith(extension) for extension in _TEXT_EXTENSIONS):
        return True

    if b"\x00" in sample[:4096]:
        return False

    return False


def _decode_text_sample(sample: bytes) -> str:
    return sample.decode("utf-8", errors="ignore")


def _match_patterns(text: str, patterns: list[str]) -> list[str]:
    matched_patterns: list[str] = []

    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            matched_patterns.append(pattern)

    return matched_patterns
