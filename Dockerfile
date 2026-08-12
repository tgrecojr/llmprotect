# syntax=docker/dockerfile:1.26@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# llmprotect guard sidecar — Chainguard python, uv-managed venv, nonroot.
# Renovate keeps builder (:latest-dev) and runtime (:latest) in lockstep so
# the venv's interpreter always matches the runtime Python.

FROM cgr.dev/chainguard/python:latest-dev@sha256:7b79c054afd14f566d1d52ea1d4d037267ec8570efedbc6ead779d89ba943abe AS builder

USER root

COPY --from=ghcr.io/astral-sh/uv:0.11@sha256:77280f2f771df71f90786c314fe1bbc1e023feac652969bbf139c280babf2eb7 /uv /uvx /usr/local/bin/

WORKDIR /app

ENV UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

COPY pyproject.toml uv.lock ./

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --group ml --no-install-project --no-editable

COPY src ./src

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --group ml --no-editable

# /cache holds the HF model download (mounted as a named volume in compose);
# it must exist in the image owned by nonroot or the volume inherits root.
RUN mkdir -p /cache && chown -R nonroot:nonroot /app /cache

FROM cgr.dev/chainguard/python:latest@sha256:69437de912cc3b5d36a2480b8fb0c3f658f151d8bc1978d19a6412be3a4983d5

WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /app/.venv /app/.venv
COPY --from=builder --chown=nonroot:nonroot /cache /cache

ENV PATH="/app/.venv/bin:$PATH" \
    HF_HOME=/cache \
    PYTHONUNBUFFERED=1

EXPOSE 8080

# Generous start period: first boot downloads the classifier model into /cache.
HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=600s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4)"]

ENTRYPOINT []
CMD ["uvicorn", "guard_api.main:app", "--host", "0.0.0.0", "--port", "8080"]
