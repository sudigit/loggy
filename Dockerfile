FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Syslog UDP + HTTP API. No outbound network calls are made by the app
# itself at runtime -- this image is safe to run fully air-gapped.
EXPOSE 5514/udp 8080/tcp

ENV ULPF_BASE_DIR=/app
ENV ULPF_DATA_DIR=/app/data

CMD ["python", "-m", "src.main"]
