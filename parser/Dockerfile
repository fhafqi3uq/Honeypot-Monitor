FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# geoip/*.mmdb is excluded via .dockerignore (a 65MB binary that changes
# independently of the code) - mount it as a read-only volume at runtime
# instead (see docker-compose.yml), same for the Cowrie log file.

EXPOSE 8000

# Default command runs the API - other parser-based services
# (log_watcher.py, cleanup.py) override this in docker-compose.yml.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
