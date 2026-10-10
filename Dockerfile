# ==============================================================================
# PortWatch — Production Multi-Stage Hardened Container Definition
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build & Dependency Resolution Environment
# ------------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install minimal toolchain required for potential C extension builds
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install dependencies into dedicated prefix directory for clean transfer
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt


# ------------------------------------------------------------------------------
# Stage 2: Minimal Production Runtime Container
# ------------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORTWATCH_ENV=production \
    PORT=5000 \
    PATH="/usr/local/bin:$PATH"

WORKDIR /app

# Copy installed Python packages and binaries from the builder stage
COPY --from=builder /install /usr/local

# Install minimal OS runtime utilities required for ICMP ping sweeps and HTTP healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
    net-tools \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Create an unprivileged non-root service user for enhanced security
RUN groupadd -g 1001 portwatch && \
    useradd -u 1001 -g portwatch -m -s /bin/bash portwatch

# Copy application codebase with ownership
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
