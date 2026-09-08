from typing import Annotated

from fastapi import APIRouter, Depends, Query, HTTPException
from starlette import status

from intelligence_scanner.services.api.dependencies import get_repository
from intelligence_scanner.services.api.repositories import ApiReadRepository
from intelligence_scanner.services.api.schemas import (
    PackageListItem,
    PackageDetail,
    PackageVersionResponse,
    ScanResultResponse,
    PaginationParams,
)
from intelligence_scanner.enums import RiskLevelEnum, FindingCategoryEnum

router = APIRouter(
    prefix="/packages",
    tags=["packages"],
    generate_unique_id_function=lambda route: route.name,
)


@router.get("/", response_model=list[PackageListItem])
async def list_packages(
    repository: Annotated[ApiReadRepository, Depends(get_repository)],
    paginator: PaginationParams = Depends(),
    name: str | None = None,
    min_score: Annotated[int | None, Query(ge=1, le=100)] = None,
    risk_level: RiskLevelEnum | None = None,
    category: FindingCategoryEnum | None = None,
) -> list[PackageListItem]:
    documents = await repository.list_packages(
        limit=paginator.limit,
        offset=paginator.offset,
        name=name,
        min_score=min_score,
        risk_level=risk_level,
        category=category,
    )

    return documents


@router.get(
    "/{package_name}",
    response_model=PackageDetail,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Package not found"},
    },
)
async def get_package(
    package_name: str,
    repository: Annotated[ApiReadRepository, Depends(get_repository)],
) -> PackageDetail:
    document = await repository.get_package(package_name)

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Package not found",
        )

    return document


@router.get("/{package_name}/versions", response_model=list[PackageVersionResponse])
async def list_package_versions(
    package_name: str,
    repository: Annotated[ApiReadRepository, Depends(get_repository)],
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[PackageVersionResponse]:
    documents = await repository.list_package_versions(
        package_name=package_name,
        limit=limit,
        offset=offset,
    )

    return documents


@router.get(
    "/{package_name}/versions/{version}",
    response_model=PackageVersionResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Package version not found"},
    },
)
async def get_package_version(
    package_name: str,
    version: str,
    repository: Annotated[ApiReadRepository, Depends(get_repository)],
) -> PackageVersionResponse:
    document = await repository.get_package_version(
        package_name=package_name,
        version=version,
    )

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Package version not found",
        )

    return document


@router.get(
    "/{package_name}/versions/{version}/scan-result",
    response_model=ScanResultResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Scan result not found"},
    },
)
async def get_scan_result(
    package_name: str,
    version: str,
    repository: Annotated[ApiReadRepository, Depends(get_repository)],
) -> ScanResultResponse:
    document = await repository.get_scan_result(
        package_name=package_name,
        version=version,
    )

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan result not found",
        )

    return document
