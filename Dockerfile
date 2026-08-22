FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080
WORKDIR /app

COPY pyproject.toml README.md ./
COPY sentinel ./sentinel
COPY web ./web
RUN pip install --no-cache-dir .

EXPOSE 8080
CMD ["sh", "-c", "uvicorn sentinel.app:app --host 0.0.0.0 --port ${PORT}"]
