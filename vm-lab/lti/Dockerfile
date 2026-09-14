FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY lti/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (flat /app so uvicorn main:app still works)
COPY lti/main.py .
COPY lti/launch_context.py .
COPY lti/persist_cell.py .
COPY api/session_keys.py .
COPY lti/lti13_config.json* ./

# Copy templates and static files for instructor dashboard
COPY lti/templates/ ./templates/
COPY lti/static/ ./static/

# Create directories for keys and config
RUN mkdir -p /app/keys

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/lti/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
