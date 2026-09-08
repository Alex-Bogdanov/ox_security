from enum import StrEnum


class ScanReasonEnum(StrEnum):
    NEW_PACKAGE = "new-package"
    NEW_VERSION = "new-version"
    MANUAL = "manual"


class PackageSourceTypeEnum(StrEnum):
    MEYOND_README = "meyond-readme"
    PLAIN_TEXT = "plain-text"
    JSON = "json"


class FindingCategoryEnum(StrEnum):
    SIZE_CHANGE = "size-change"

    INSTALL_HOOK_ADDED = "install-hook-added"
    INSTALL_HOOK_EXISTING = "install-hook-existing"
    INSTALL_HOOK_REMOVED = "install-hook-removed"

    BINARY_EXECUTABLE = "binary-executable"
    COMMAND_EXECUTION = "command-execution"
    SHELL_COMMAND = "shell-command"
    OBFUSCATION = "obfuscation"

    SCAN_LIMIT_REACHED = "scan-limit-reached"
    METADATA_ANOMALY = "metadata-anomaly"


class RiskLevelEnum(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingSeverityEnum(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BinaryTypeEnum(StrEnum):
    ELF = "elf"
    PE = "pe"
    PE_EXE = "pe-exe"
    PE_DLL = "pe-dll"
    NATIVE_NODE_ADDON = "native-node-addon"
    ELF_SHARED_OBJECT = "elf-shared-object"
    MACHO_DYLIB = "mach-o-dylib"
