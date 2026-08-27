ARG PYTHON_VERSION=3.12.7
ARG UV_VERSION=0.11.21

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv
FROM python:${PYTHON_VERSION}-slim-bookworm AS base

ENV LC_ALL=C.UTF-8 \
    LANG=C.UTF-8

## PYTHON
# Seems to speed things up
ENV PYTHONUNBUFFERED=1
# Turns off writing .pyc files. Superfluous on an ephemeral container.
ENV PYTHONDONTWRITEBYTECODE=1

# Ensures that the Python executable used
# in the image will be those from our virtualenv.
ENV PATH="/venv/bin:$PATH"

FROM base AS builder
COPY --from=uv /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/venv

WORKDIR /app

# Install OS package dependencies.
# Do all of this in one RUN to limit final image size.
RUN set -ex &&  \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc gettext && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./

RUN uv sync --locked --no-dev --no-install-project

FROM base AS base-app

# 安装运行时依赖
RUN set -ex &&  \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        gettext curl vim && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
USER root

ADD ./ ./

# 拷贝构件
COPY --from=builder /venv /venv


FROM base-app AS app
ENTRYPOINT ["scripts/docker-entrypoint.sh"]
