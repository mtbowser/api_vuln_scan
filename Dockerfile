# Dockerfile
FROM python:3.9-slim

WORKDIR /api_vuln_scan

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

ENTRYPOINT ["python", "api_security_scanner.py"]

# Use CMD as default arguments
CMD ["--help"]