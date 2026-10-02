# ==============================================================================
# PortWatch — Production Docker Container Definition
# Multi-stage security hardened deployment container with non-root runtime
# ==============================================================================

FROM python:3.11-slim-bookworm AS base

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORTWATCH_ENV=production \
    PORT=5000

WORKDIR /app

# Install minimal OS utilities required for ICMP ping sweeps and HTTP healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python production dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create an unprivileged non-root service user for enhanced security
RUN groupadd -g 1001 portwatch && \
    useradd -u 1001 -g portwatch -m -s /bin/bash portwatch

# Copy application codebase
COPY --chown=portwatch:portwatch . .

# Grant non-root user permission to perform raw socket pings via capabilities
RUN setcap cap_net_raw+ep /bin/ping 2>/dev/null || true

# Switch to unprivileged runtime user
USER portwatch

EXPOSE 5000

# Automated container healthcheck validating database and API responsiveness
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Production WSGI server invocation via Gunicorn (2 worker processes, 4 threads per worker)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-", "app:create_app()"]
