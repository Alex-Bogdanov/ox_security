import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import sys
from fastapi import FastAPI

from intelligence_scanner.services.api.routes.health import router as health_router
from intelligence_scanner.services.api.routes.packages import router as packages_router
from intelligence_scanner.services.api.routes.scan_jobs import router as scan_jobs_router
from intelligence_scanner.services.api.routes.scan_results import router as scan_results_router
from intelligence_scanner.db.mongo import ensure_indexes, mongo_database
from intelligence_scanner.settings import get_settings

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()

    async with mongo_database(settings) as database:
        await ensure_indexes(database)
        app.state.database = database
        yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="NPM Intelligence Scanner API",
        version="0.1.0",
        description="API for browsing NPM package scan jobs, scan results, and risk findings.",
        lifespan=lifespan,
    )

    app.include_router(health_router)
    app.include_router(packages_router)
    app.include_router(scan_jobs_router)
    app.include_router(scan_results_router)

    logger.info("API service created!")
    return app


app = create_app()
