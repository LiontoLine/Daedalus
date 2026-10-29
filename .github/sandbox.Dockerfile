# CI task runtime: host dependencies are not available inside an isolated container.
FROM node:24-bookworm-slim AS node-runtime
FROM python:3.12-slim
COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node-runtime /usr/local/LICENSE /usr/local/share/doc/node/LICENSE
RUN python -m pip install --no-cache-dir "pytest>=8"
ENV PYTHONDONTWRITEBYTECODE=1
