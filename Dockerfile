# Single image; serves the synthetic demo by default. Publish only on 127.0.0.1 (see docs/en/installation.md).
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.6.14 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:$PATH" TIW_DATA_DIR=/data/demo
VOLUME ["/data"]
EXPOSE 8787
RUN useradd --create-home tiw && mkdir -p /data && chown tiw /data
USER tiw
# The container is the isolation boundary, so bind all interfaces inside it.
CMD ["sh", "-c", "tiw demo seed --scenario all --data-dir $TIW_DATA_DIR && tiw demo advance --step 4 --data-dir $TIW_DATA_DIR && python -c \"import uvicorn; from tiw.api.app import create_app; from tiw.storage.db import resolve_workspace; uvicorn.run(create_app(resolve_workspace(), port=8787, extra_hosts=('localhost:8787','127.0.0.1:8787')), host='0.0.0.0', port=8787)\""]
