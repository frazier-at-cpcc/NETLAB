FROM debian:bookworm

WORKDIR /app

# Install Python and system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-libvirt \
    python3-venv \
    curl \
    qemu-utils \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python packages (skip libvirt-python since we use system package)
RUN grep -v '^#' requirements.txt | grep -v '^$' | grep -v libvirt-python > /tmp/reqs.txt && \
    pip install --no-cache-dir --break-system-packages -r /tmp/reqs.txt

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
