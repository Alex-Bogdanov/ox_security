from typing import Annotated

from fastapi import Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from starlette.requests import Request

from .repositories import ApiReadRepository


def get_database(request: Request) -> AsyncIOMotorDatabase:
    return request.app.state.database


def get_repository(
    database: Annotated[AsyncIOMotorDatabase, Depends(get_database)],
) -> ApiReadRepository:
    return ApiReadRepository(database)
