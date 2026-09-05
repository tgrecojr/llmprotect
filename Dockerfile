# syntax=docker/dockerfile:1.27@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e
# llmprotect guard sidecar — Chainguard python, uv-managed venv, nonroot.
# Renovate keeps builder (:latest-dev) and runtime (:latest) in lockstep so
# the venv's interpreter always matches the runtime Python.

FROM cgr.dev/chainguard/python:latest-dev@sha256:f6d6485f11a65ca81d8a2d01eae564fa88937e7d19c1cf216cdb1142980c51bd AS builder

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
# /app/data is the bind mount for opt-in traffic capture (GUARD_CAPTURE_DIR).
# Both must exist in the image owned by nonroot or the mount inherits root.
RUN mkdir -p /cache /app/data && chown -R nonroot:nonroot /app /cache

FROM cgr.dev/chainguard/python:latest@sha256:069011a0d23f43c1cb6fbee4e1d21f741107db4ba60c298258290b46ceefdcba

WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /app/.venv /app/.venv
COPY --from=builder --chown=nonroot:nonroot /cache /cache
COPY --from=builder --chown=nonroot:nonroot /app/data /app/data

ENV PATH="/app/.venv/bin:$PATH" \
    HF_HOME=/cache \
    PYTHONUNBUFFERED=1

EXPOSE 8080

# Generous start period: first boot downloads the classifier model into /cache.
HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=600s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4)"]

ENTRYPOINT []
CMD ["uvicorn", "guard_api.main:app", "--host", "0.0.0.0", "--port", "8080"]
