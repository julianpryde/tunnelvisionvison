# Self-contained TunnelVision lab (Linux kernel required: Docker Desktop's VM works).
#   docker build -t tvv-lab -f lab/Dockerfile .
#   docker run --rm --privileged tvv-lab
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 dnsmasq isc-dhcp-client python3 procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/tvv
COPY tunnelvisionvision ./tunnelvisionvision
COPY lab/run-lab.sh ./run-lab.sh
CMD ["bash", "/opt/tvv/run-lab.sh"]
