# =============================================================================
# Bastion-Agent runtime image
# One image serves both the FastAPI gateway and the ARQ worker; the compose
# `command` selects the process. Built as a non-root user.
# =============================================================================
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

# libgomp1 is required by onnxruntime; nothing else is needed at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 bastion \
 && useradd --uid 10001 --gid bastion --create-home --shell /usr/sbin/nologin bastion

COPY --from=ghcr.io/astral-sh/uv:0.5.13 /uv /uvx /bin/

WORKDIR /app

# Dependency layer: cached independently of application source changes.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# Application layer. The venv stays root-owned but world-readable; the source
# tree is owned by the runtime user so editable installs resolve normally.
COPY --chown=bastion:bastion pyproject.toml README.md settings.py logging_setup.py telemetry.py ./
COPY --chown=bastion:bastion db ./db
COPY --chown=bastion:bastion gateway ./gateway
COPY --chown=bastion:bastion agent ./agent
# ADR-009 Gate 1: the image carries the approved tool allow-list, and startup
# refuses to run if the registry and this catalog disagree.
COPY --chown=bastion:bastion docs ./docs
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

USER bastion

EXPOSE 8000

CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]

# =============================================================================
# GPU variant (ADR-011): the same image with onnxruntime-gpu instead of the CPU
# wheel, so a CUDA session can run the fp32 graphs. The CPU execution provider
# stays in the wheel, which is the fallback when no device is visible.
#
#   docker build --target runtime-gpu -t bastion-agent:gpu .
#   docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d
#
# The CPU wheel is removed first: both distributions install the `onnxruntime`
# package, and uninstalling after the GPU wheel would delete shared files.
# =============================================================================
FROM runtime AS runtime-gpu

USER root
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip uninstall --python /app/.venv/bin/python onnxruntime \
 && uv pip install --python /app/.venv/bin/python --no-cache-dir \
      "onnxruntime-gpu[cuda,cudnn]==1.31.1"
USER bastion
