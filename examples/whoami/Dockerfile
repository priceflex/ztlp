FROM python:3.12-alpine
WORKDIR /app
COPY app.py /app/app.py
USER 65534:65534
ENV PORT=8080 BIND=0.0.0.0 PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/up || exit 1
CMD ["python3", "/app/app.py"]
