FROM node:22-alpine AS frontend-build
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements-render.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY backend/ /app/backend/
COPY data/ /app/data/
COPY --from=frontend-build /frontend/dist/ /app/frontend/dist/
ENV PYTHONPATH=/app/backend FLASK_HOST=0.0.0.0 PORT=10000 DATA_SOURCE=demo
EXPOSE 10000
WORKDIR /app/backend
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 4 --timeout 120 run:app"]
