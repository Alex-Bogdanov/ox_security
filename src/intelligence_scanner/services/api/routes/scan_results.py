from typing import Annotated

from fastapi import Depends, Query, APIRouter

from intelligence_scanner.services.api.dependencies import get_repository
from intelligence_scanner.services.api.repositories import ApiReadRepository
from intelligence_scanner.services.api.schemas import ScanResultResponse, PaginationParams
from intelligence_scanner.enums import RiskLevelEnum, FindingCategoryEnum

router = APIRouter(
    prefix="/scan-results",
    tags=["scan-results"],
    generate_unique_id_function=lambda route: route.name,
)


@router.get("/", response_model=list[ScanResultResponse])
async def list_scan_results(
    repository: Annotated[ApiReadRepository, Depends(get_repository)],
    paginator: PaginationParams = Depends(),
    package_name: str | None = None,
    min_score: Annotated[int | None, Query(ge=1, le=100)] = None,
    risk_level: RiskLevelEnum | None = None,
    category: FindingCategoryEnum | None = None,
) -> list[ScanResultResponse]:
    documents = await repository.list_scan_results(
        limit=paginator.limit,
        offset=paginator.offset,
        package_name=package_name,
        min_score=min_score,
        risk_level=risk_level,
        category=category,
    )

    return documents
