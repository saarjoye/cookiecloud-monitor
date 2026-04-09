FROM node:20-alpine AS frontend-builder

WORKDIR /build

COPY frontend/package.json ./frontend/package.json
COPY frontend/vite.config.js ./frontend/vite.config.js
COPY frontend/src ./frontend/src
COPY app/static ./app/static

RUN cd frontend && npm install --no-fund --no-audit && npm run build

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY --from=frontend-builder /build/app/static/login-app ./app/static/login-app

EXPOSE 8090

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
