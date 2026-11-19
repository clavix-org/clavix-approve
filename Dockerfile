# The relay and the approval page it serves. Meant to run behind a
# TLS-terminating reverse proxy, as an unprivileged user, on a read-only
# root filesystem: the only path written to is the state volume.
FROM python:3.13-slim

# httpx[http2]: APNs, for the iOS app, is HTTP/2 only.
RUN pip install --no-cache-dir "cryptography>=43,<47" "httpx[http2]>=0.27,<1" \
    && mkdir /state && chown 10001:10001 /state

# The release tag, shown at the bottom of the page.
ARG VERSION=dev

COPY relay/relay.py /app/relay/relay.py
COPY web/ /app/web/

ENV RELAY_BIND=0.0.0.0 \
    RELAY_PORT=8765 \
    RELAY_STATE_DIR=/state \
    RELAY_WEB_DIR=/app/web \
    RELAY_VERSION=$VERSION \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Enrolment is open unless RELAY_ENROLL_SECRET is set; a public instance
# also sets RELAY_SERVE_WEB=off and its client address header or proxies.
# Every setting and limit is listed at the top of relay.py and in README.
USER 10001:10001
VOLUME /state
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
    CMD ["python3", "/app/relay/relay.py", "--healthcheck"]
CMD ["python3", "/app/relay/relay.py"]
