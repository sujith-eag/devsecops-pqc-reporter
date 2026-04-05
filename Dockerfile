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
# Pinning WeasyPrint to the stable 68.x branch
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    weasyprint==68.1 \
    Jinja2 \
    pandas \
    matplotlib \
    seaborn

# Setup application directory
WORKDIR /app

# Copy the entire source directory into the container
COPY src/ /app/src/

# The execution command points to the new orchestrator
ENTRYPOINT ["python", "/app/src/main.py"]