# threat-intel-workbench. Publish only on 127.0.0.1:  docker run -p 127.0.0.1:8787:8787 ...
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.6.14 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:$PATH" TIW_MODE=live TIW_DATA_DIR=/data/workspace
RUN useradd --create-home tiw && mkdir -p /data && chown tiw /data
USER tiw
VOLUME ["/data"]
EXPOSE 8787
CMD ["python", "-m", "tiw.container"]
