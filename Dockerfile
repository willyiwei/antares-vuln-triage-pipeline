FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir . 2>/dev/null || pip install --no-cache-dir -e .

COPY src/ ./src/
COPY config/ ./config/
COPY data/ ./data/
COPY dashboard/ ./dashboard/
COPY reports/ ./reports/

EXPOSE 8181

ENV PYTHONUNBUFFERED=1

CMD ["antares-triage", "dashboard", "--host", "0.0.0.0", "--port", "8181"]
