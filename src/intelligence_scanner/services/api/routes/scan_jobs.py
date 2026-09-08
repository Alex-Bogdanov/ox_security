from typing import Annotated

from fastapi import Depends, Query, HTTPException, APIRouter
from starlette import status

from intelligence_scanner.services.api.dependencies import get_repository
from intelligence_scanner.services.api.repositories import ApiReadRepository
from intelligence_scanner.services.api.schemas import ScanJobResponse, PaginationParams
from intelligence_scanner.db.schemas import ScanJobStatus

router = APIRouter(
    prefix="/scan-jobs",
    tags=["scan-jobs"],
    generate_unique_id_function=lambda route: route.name,
)


@router.get("/", response_model=list[ScanJobResponse])
async def list_scan_jobs(
    repository: Annotated[ApiReadRepository, Depends(get_repository)],
    paginator: PaginationParams = Depends(),
    package_name: str | None = None,
    status_: ScanJobStatus | None = Query(default=None, alias="status"),
) -> list[ScanJobResponse]:
    documents = await repository.list_scan_jobs(
        limit=paginator.limit,
        offset=paginator.offset,
        package_name=package_name,
        status=status_,
    )

    return documents


@router.get(
    "/{job_id}",
    response_model=ScanJobResponse,
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "Scan job not found"},
    },
)
async def get_scan_job(
    job_id: str,
    repository: Annotated[ApiReadRepository, Depends(get_repository)],
) -> ScanJobResponse:
    document = await repository.get_scan_job(job_id)

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan job not found",
        )

    return document
