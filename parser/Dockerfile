FROM python:3.12-slim

WORKDIR /app

# mongodump (parser/backup.py) - not bundled in mongodb-org since Mongo 6+,
# and the base image's Debian release (trixie) isn't in MongoDB's official
# apt repo yet, so this pulls the standalone .deb directly instead (the
# debian12 build works fine here - verified against this exact base image).
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && curl -fsSL https://fastdl.mongodb.org/tools/db/mongodb-database-tools-debian12-x86_64-100.14.0.deb -o /tmp/mongodb-database-tools.deb \
    && apt-get install -y --no-install-recommends /tmp/mongodb-database-tools.deb \
    && rm -rf /tmp/mongodb-database-tools.deb /var/lib/apt/lists/*

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
