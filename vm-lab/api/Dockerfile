FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including libvirt
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libvirt-dev \
    pkg-config \
    gcc \
    python3-dev \
    qemu-utils \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .

# Create directories
RUN mkdir -p /app/keys

# Note: This container runs as root because it needs:
# - Access to libvirt socket
# - Access to Docker socket
# - Access to /var/lib/libvirt/images

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
