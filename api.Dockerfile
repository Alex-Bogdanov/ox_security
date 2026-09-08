FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app/src
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

WORKDIR /app

COPY pyproject.toml uv.lock ./

RUN uv sync --frozen --no-dev --extra api --no-install-project

COPY src ./src

RUN uv sync --frozen --no-dev --extra api

CMD ["uv", "run", "--no-sync", "uvicorn", "intelligence_scanner.services.api.main:app", "--reload", "--loop", "uvloop", "--host", "0.0.0.0", "--port", "8000"]
