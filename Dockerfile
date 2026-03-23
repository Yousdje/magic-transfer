FROM python:3.11-slim AS base

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY server.py .

# ============= Test stage =============
FROM base AS test
COPY test_server.py pytest.ini ./
RUN mkdir -p /input /output && chmod 750 /input /output
CMD ["pytest", "-v", "test_server.py"]

# ============= Production stage =============
FROM base AS production

# Security: Create non-root user first
RUN useradd -m -u 1000 appuser

# Create directories with proper permissions
RUN mkdir -p /input /output/uploads /output/downloads \
    && chown -R appuser:appuser /input /output \
    && chmod 750 /input /output /output/uploads /output/downloads
RUN chown -R appuser:appuser /app

# Render uses dynamic PORT; keep 8080 as fallback
EXPOSE 8080
USER appuser

# Health check — use PORT env var if set
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://localhost:{os.environ.get(\"PORT\",8080)}/health')"

# Run application
CMD ["python", "-u", "server.py"]
