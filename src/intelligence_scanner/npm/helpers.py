from datetime import datetime
from typing import Any


def get_version_metadata(
    package_metadata: dict[str, Any],
    version: str,
) -> dict[str, Any] | None:
    versions = package_metadata.get("versions")

    if not isinstance(versions, dict):
        return None

    version_metadata = versions.get(version)
    return version_metadata if isinstance(version_metadata, dict) else None


def get_published_at(
    package_metadata: dict[str, Any],
    version: str,
) -> datetime | None:
    time_mapping = package_metadata.get("time")

    if not isinstance(time_mapping, dict):
        return None

    raw_value = time_mapping.get(version)

    if not isinstance(raw_value, str):
        return None

    normalized = raw_value.replace("Z", "+00:00")

    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def get_dist_info(version_metadata: dict[str, Any]) -> dict[str, Any]:
    dist = version_metadata.get("dist")
    return dist if isinstance(dist, dict) else {}


def get_package_json_subset(version_metadata: dict[str, Any]) -> dict[str, Any]:
    keys = {
        "name",
        "version",
        "description",
        "keywords",
        "homepage",
        "bugs",
        "license",
        "author",
        "contributors",
        "maintainers",
        "repository",
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "bundledDependencies",
        "bundleDependencies",
        "scripts",
        "bin",
        "main",
        "module",
        "types",
        "exports",
        "engines",
        "os",
        "cpu",
    }

    return {key: version_metadata[key] for key in keys if key in version_metadata}


def get_scripts(version_metadata: dict[str, Any]) -> dict[str, Any]:
    scripts = version_metadata.get("scripts")
    return scripts if isinstance(scripts, dict) else {}


def get_dependencies(version_metadata: dict[str, Any]) -> dict[str, Any]:
    dependencies = version_metadata.get("dependencies")
    return dependencies if isinstance(dependencies, dict) else {}


def get_package_size(version_metadata: dict[str, Any]) -> int | None:
    dist = version_metadata.get("dist")

    if not isinstance(dist, dict):
        return None

    unpacked_size = dist.get("unpackedSize")

    if isinstance(unpacked_size, int):
        return unpacked_size

    file_count_size = dist.get("fileCount")

    if isinstance(file_count_size, int):
        return file_count_size

    return None


def get_latest_version(metadata: dict[str, Any]) -> str | None:
    dist_tags = metadata.get("dist-tags")

    if not isinstance(dist_tags, dict):
        return None

    latest = dist_tags.get("latest")
    return latest if isinstance(latest, str) and latest else None
