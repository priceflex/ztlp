FROM python:3.12-alpine

# Install docker CLI + compose plugin so the launch app can provision per-zone
# bootstrap stacks via docker-in-docker (host socket mounted in docker-compose.yml).
# We do NOT install the docker daemon — only the client tools.
RUN apk add --no-cache docker-cli docker-cli-compose

RUN addgroup -S launch && adduser -S -G launch -h /app launch

WORKDIR /app
COPY --chown=launch:launch launch_app ./launch_app
RUN mkdir -p /app/data && chown -R launch:launch /app

# Group `docker` (created with a fixed GID matching the host socket's GID)
# is added to the launch user so the bind-mounted /var/run/docker.sock is
# accessible. The matching GID is supplied at compose time via group_add.
ENV PYTHONUNBUFFERED=1 \
    LAUNCH_BIND_HOST=0.0.0.0 \
    LAUNCH_BIND_PORT=8080 \
    LAUNCH_DB_PATH=/app/data/launch.sqlite3

USER launch
EXPOSE 8080
CMD ["python", "-m", "launch_app.app"]
