# Base Python image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy TLS certs (created on host, e.g., via mkcert) into /certs in container
# certs/ should contain: cert.pem and key.pem
COPY certs /certs

# Expose Flask HTTPS port
EXPOSE 5000

# Start the app
CMD ["python", "app.py"]
