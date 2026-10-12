# ==============================================================================
# API Sentinel - Production Dockerfile
# Multi-stage / optimized single-stage build using Python 3.11 slim
# ==============================================================================

FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=1000 \
    HOST=0.0.0.0 \
    PORT=8000 \
    ENVIRONMENT=production \
    DEBUG=false \
    STORAGE_BACKEND=memory \
    ML_MODEL_PATH=models/isolation_forest.joblib \
    ML_METADATA_PATH=models/model_metadata.json

# Working directory
WORKDIR /app

# Security best practice: Create a dedicated non-root user and group (UID 1001)
RUN groupadd -r appgroup && useradd -r -g appgroup -u 1001 -m -d /home/appuser appuser

# Install dependencies first to maximize Docker layer cache efficiency
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --default-timeout=1000 --retries=10 -r requirements.txt

# Copy application source code, scripts, and model assets
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY models/ ./models/

# Ensure ML model artifacts exist; if absent from the build context, train deterministically
RUN if [ ! -f models/isolation_forest.joblib ]; then \
        echo "ML model artifact not found in build context. Training deterministic baseline model..." && \
        python scripts/train_isolation_forest.py --output-dir models --samples 1500 --seed 42; \
    fi

# Set directory permissions for the non-root application user
RUN chown -R appuser:appgroup /app /home/appuser

# Switch to the non-root user
USER appuser

# Expose default application port
EXPOSE 8000

# Container healthcheck querying /health via Python standard library
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, os, sys; port = os.getenv('PORT', '8000'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=3).getcode() == 200 else 1)"

# Start Uvicorn ASGI server with configurable host and port
CMD ["sh", "-c", "exec uvicorn app.main:app --host ${HOST:-0.0.0.0} --port ${PORT:-8000}"]
