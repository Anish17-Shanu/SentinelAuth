FROM python:3.12-slim

LABEL org.opencontainers.image.title="SentinelAuth"
LABEL org.opencontainers.image.authors="ANISH KUMAR"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "services.auth_server.app:app", "--host", "0.0.0.0", "--port", "8000"]
