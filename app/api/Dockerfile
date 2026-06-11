# Build from the repo root so the shared cedar/ policies are in context:
#   docker build -t cloudsec-api:local -f app/api/Dockerfile .
FROM python:3.12-slim AS base

# Non-root, high UID (passes the namespace's restricted Pod Security).
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY app/api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/api/main.py /app/main.py
# Same Cedar artifacts unit-tested in cedar/authz.py — single source of truth.
COPY cedar/policies.cedar cedar/schema.json cedar/entities.json /app/cedar/

USER 10001
EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
