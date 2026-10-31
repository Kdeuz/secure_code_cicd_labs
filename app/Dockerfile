FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DB_PATH=/data/shop.db
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 appuser && mkdir /data && chown appuser:appuser /data

COPY app/requirements.txt .
RUN pip install --require-hashes --no-cache-dir -r requirements.txt

COPY app/ .

USER appuser
EXPOSE 5000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
