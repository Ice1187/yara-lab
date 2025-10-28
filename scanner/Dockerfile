FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    wget \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Download and install yara-x
RUN wget https://github.com/VirusTotal/yara-x/releases/download/v1.8.1/yara-x-v1.8.1-x86_64-unknown-linux-gnu.gz \
    && tar -xzf yara-x-v1.8.1-x86_64-unknown-linux-gnu.gz \
    && mv yr /usr/local/bin/ \
    && chmod +x /usr/local/bin/yr \
    && rm yara-x-v1.8.1-x86_64-unknown-linux-gnu.gz

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000

CMD ["python", "app.py"]

