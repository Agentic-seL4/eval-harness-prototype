FROM python:3.12-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.9.17 /uv /usr/local/bin/uv

ARG AGENTDOJO_REVISION=089ed468cf3ed0322acc66b0211f26d9d90dbf60
LABEL org.opencontainers.image.revision=$AGENTDOJO_REVISION

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    PATH="/opt/agentdojo/.venv/bin:$PATH"

WORKDIR /opt/agentdojo
COPY agentdojo/pyproject.toml agentdojo/uv.lock agentdojo/README.md ./
COPY agentdojo/src ./src
COPY agentdojo/tests ./tests
RUN uv sync --locked --no-editable --group dev \
    && useradd --create-home --uid 1000 researcher

USER researcher
CMD ["sleep", "infinity"]
