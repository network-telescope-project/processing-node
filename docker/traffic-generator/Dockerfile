FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    hping3 \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy

COPY traffic_generator.py /traffic_generator.py

CMD ["python", "/traffic_generator.py"]
