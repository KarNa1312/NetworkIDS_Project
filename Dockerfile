# Dockerfile
FROM python:3.10-slim

LABEL maintainer="Your Name <you@example.com>"

# Prevent Python from writing .pyc and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy only requirements first (for caching)
COPY requirements.txt /app/requirements.txt

# Install system dependencies (needed by some Python packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the entire repo into the image
COPY . /app

<<<<<<< HEAD
# Configure which Streamlit file to run (change if your file location differs)
ENV STREAMLIT_ENTRYPOINT=app/realtime_detector1.py

=======
# Set default Streamlit entrypoint
ENV STREAMLIT_ENTRYPOINT=app/realtime_detector1.py
>>>>>>> 324e6b131986dd4b324dabf721cc8a689dbe3715

EXPOSE 8501

CMD ["bash", "-lc", "streamlit run $STREAMLIT_ENTRYPOINT --server.port=8501 --server.address=0.0.0.0"]
