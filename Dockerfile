# PacketLens - packet capture analysis web tool
FROM python:3.11-slim

# Scapy needs libpcap for live capture; it is not strictly required just
# to *read* pcap/pcapng files, but tcpdump/libpcap are installed here so
# the container also works for live-capture style use cases and so
# Scapy's optional native extensions have what they need at import time.
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=wsgi.py \
    PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
