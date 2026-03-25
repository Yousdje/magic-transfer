FROM python:3.11-slim AS base

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

# ============= Test stage =============
FROM base AS test
COPY test_server.py pytest.ini ./
RUN mkdir -p /output/uploads && chmod 750 /output /output/uploads
CMD ["pytest", "-v", "test_server.py"]

# ============= Production stage =============
FROM base AS production

# Security: non-root user
RUN useradd -m -u 1000 appuser

# Create directories with proper permissions
RUN mkdir -p /output/uploads \
    && chown -R appuser:appuser /output \
    && chmod 750 /output /output/uploads
RUN chown -R appuser:appuser /app

EXPOSE 8080
USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://localhost:{os.environ.get(\"PORT\",8080)}/health')"

CMD ["python", "-u", "server.py"]
