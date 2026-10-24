FROM python:3.12-slim AS backend
WORKDIR /app
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend /app/backend
COPY data /app/data
ENV PYTHONPATH=/app/backend API_PORT=5000 FLASK_HOST=0.0.0.0
EXPOSE 5000
CMD ["python", "/app/backend/run.py"]
