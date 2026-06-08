# Build + run the vulnerable app. Kept minimal so awspt's assess "build & run"
# step (Docker sandbox) can stand it up and scan it.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="awspt-vuln-lab"
LABEL org.opencontainers.image.description="Intentionally vulnerable web app for awspt end-to-end testing — DO NOT DEPLOY publicly."

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=2).status==200 else 1)"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
