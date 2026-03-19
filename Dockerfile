FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project files
COPY pyproject.toml .
COPY src/ src/
COPY web/ web/

# Install dependencies
RUN uv pip install --system --no-cache .

# Expose port
EXPOSE ${PORT:-8000}

# Run the API server — use shell form so $PORT is expanded
CMD uvicorn mcpshield.api.app:app --host 0.0.0.0 --port ${PORT:-8000}
