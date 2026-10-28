# Custom hardened worker image — NOT the Playwright dev image
FROM python:3.11-slim-bookworm

# Create non-root user FIRST
RUN groupadd -r phishguard && useradd -r -g phishguard -m -s /bin/bash worker

# Install Chromium and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    fonts-liberation \
    libnss3 \
    libxss1 \
    libasound2 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements-sandbox.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements-sandbox.txt

# Copy worker code
COPY worker.py /app/worker.py
WORKDIR /app

# Switch to non-root user
USER worker

# Chromium flags for sandboxed execution
ENV CHROMIUM_FLAGS="--no-sandbox --disable-gpu --disable-dev-shm-usage"
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "/app/worker.py"]
