# Secure Dockerfile for PyGoat - DevSecOps Implementation
# Base image - using specific version for security
FROM python:3.9.18-slim-bullseye

# Metadata labels
LABEL maintainer="devsecops-team"
LABEL version="1.0"
LABEL description="PyGoat - Vulnerable Django Application for Security Training"
LABEL security.scan="required"

# Create non-root user for security
RUN groupadd -r pygoat && \
    useradd -r -g pygoat -d /app -s /bin/bash pygoat

# Update system packages and install only necessary dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
        libffi-dev \
        libssl-dev \
        libpq-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set working directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Upgrade pip and install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories and set permissions
RUN mkdir -p /app/media /app/static /app/logs && \
    chown -R pygoat:pygoat /app && \
    chmod -R 755 /app && \
    chmod -R 750 /app/logs

# Remove any potential sensitive files
RUN find /app -name "*.pyc" -delete && \
    find /app -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Security: Remove package managers and compilers after installation
RUN apt-get remove -y gcc libc6-dev && \
    apt-get autoremove -y && \
    apt-get clean

# Switch to non-root user
USER pygoat

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Expose port (documentation only)
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DJANGO_SETTINGS_MODULE=pygoat.settings

# Run database migrations and start the application
CMD ["sh", "-c", "python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]