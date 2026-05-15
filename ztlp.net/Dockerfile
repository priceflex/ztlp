FROM python:3.12-alpine

RUN addgroup -S launch && adduser -S -G launch -h /app launch

WORKDIR /app
COPY --chown=launch:launch launch_app ./launch_app
RUN mkdir -p /app/data && chown -R launch:launch /app

ENV PYTHONUNBUFFERED=1 \
    LAUNCH_BIND_HOST=0.0.0.0 \
    LAUNCH_BIND_PORT=8080 \
    LAUNCH_DB_PATH=/app/data/launch.sqlite3

USER launch
EXPOSE 8080
CMD ["python", "-m", "launch_app.app"]
