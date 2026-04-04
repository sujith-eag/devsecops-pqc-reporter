# ==========================================
# DEVSECOPS REPORTING CONTAINER
# ==========================================
FROM python:3.12-slim

# Prevent Python from writing .pyc files and force stdout logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install required system dependencies for WeasyPrint & Matplotlib
# Based on official WeasyPrint Debian 12 (Bookworm) requirements
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz-subset0 \
    libjpeg-dev \
    libopenjp2-7-dev \
    libffi-dev \
    libcairo2 \
    fonts-liberation \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and install the Python stack
# Pinning WeasyPrint to the stable 68.x branch (Feb 2026)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    weasyprint==68.1 \
    Jinja2 \
    pandas \
    matplotlib \
    seaborn

# Create a non-root user for security compliance
RUN groupadd -r reporter && useradd -r -g reporter -m reporter

# Setup application directories
WORKDIR /app
RUN mkdir -p /app/templates /app/assets && \
    chown -R reporter:reporter /app

# Copy the logic scripts and templates (To be created next)
COPY report_builder.py /app/
# COPY templates/ /app/templates/

# Switch to the non-root user
USER reporter

# The execution command. It expects the /src volume to be mounted.
ENTRYPOINT ["python", "/app/report_builder.py"]
