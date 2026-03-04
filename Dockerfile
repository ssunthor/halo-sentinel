# Use official lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
# We copy requirements first to leverage Docker caching
COPY requirements.txt .
COPY *.py .

RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code and the GeoIP database
#COPY main.py .
#COPY config.py .
COPY GeoLite2-City.mmdb .
COPY feed_cache.py /usr/local/lib/python3.11/site-packages/

ENV PYTHONUNBUFFERED=1

# Expose the port FastAPI runs on
EXPOSE 5174

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5174"]
