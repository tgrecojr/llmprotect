# syntax=docker/dockerfile:1.27@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# llmprotect guard sidecar — Chainguard python, uv-managed venv, nonroot.
# Renovate keeps builder (:latest-dev) and runtime (:latest) in lockstep so
# the venv's interpreter always matches the runtime Python.

FROM cgr.dev/chainguard/python:latest-dev@sha256:96cb9c155159daf6b21e70555f244081909ff161c5589112ddf308624c1a1c77 AS builder

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

FROM cgr.dev/chainguard/python:latest@sha256:1961420e5f93bd056d4b0b40eca12cdf01b3ed09177aa4d6ec71fab38cbf158f

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
