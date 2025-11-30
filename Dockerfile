# Dockerfile for Backend (FastAPI)
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ ./backend/

# Copy requirements to backend directory
COPY requirements.txt ./backend/

# Expose port
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# Change to backend directory
WORKDIR /app/backend

# Run the application
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}

