FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default command runs the realtime alert watcher - the other notifier
# services (daily_report.py, telegram_commands.py) override this in
# docker-compose.yml.
CMD ["python", "-u", "realtime_alert.py"]
