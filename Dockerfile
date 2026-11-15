# The relay and the approval page it serves. Meant to run behind a
# TLS-terminating reverse proxy, as an unprivileged user, on a read-only
# root filesystem: the only path written to is the state volume.
FROM python:3.13-slim

RUN pip install --no-cache-dir "cryptography>=43,<47" \
    && mkdir /state && chown 10001:10001 /state

COPY relay/relay.py /app/relay/relay.py
COPY web/ /app/web/

ENV RELAY_BIND=0.0.0.0 \
    RELAY_PORT=8765 \
    RELAY_STATE_DIR=/state \
    RELAY_WEB_DIR=/app/web \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
VOLUME /state
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
    CMD ["python3", "/app/relay/relay.py", "--healthcheck"]
CMD ["python3", "/app/relay/relay.py"]
