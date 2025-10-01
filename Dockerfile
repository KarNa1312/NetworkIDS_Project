# Dockerfile (place at repo root)
FROM python:3.10-slim

LABEL maintainer="Your Name <you@example.com>"

# Prevent Python from writing .pyc and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy only requirements first (layer caching)
COPY requirements.txt /app/requirements.txt

# Install system dependencies needed for some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy project files into the image
COPY . /app

# Configure which Streamlit file to run (change if your file location differs)
ENV STREAMLIT_ENTRYPOINT=app/realtime_detector1.py


EXPOSE 8501

CMD ["bash", "-lc", "streamlit run $STREAMLIT_ENTRYPOINT --server.port=8501 --server.address=0.0.0.0"]
