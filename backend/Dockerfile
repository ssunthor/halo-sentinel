FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY llm_interface.py .
COPY db.py .
COPY email_report.py .
COPY changelog.json .
COPY fba_client.py .
COPY gia_client.py .

ENV PYTHONUNBUFFERED=1

EXPOSE 5174

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5174"]
