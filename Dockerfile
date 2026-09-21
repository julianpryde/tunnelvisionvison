# TunnelVisionVision for Linux container hosts (Docker/Podman/Kubernetes nodes).
# Run with host networking so it watches the host's routing table:
#   docker run -d --name tvv --restart unless-stopped --network host \
#     --cap-add NET_ADMIN --cap-add NET_RAW \
#     -v /var/lib/NetworkManager:/var/lib/NetworkManager:ro \
#     -v /var/lib/dhcp:/var/lib/dhcp:ro -v /run/systemd/netif:/run/systemd/netif:ro \
#     tunnelvisionvision
#   docker exec tvv tvv status
#   docker exec tvv tvv action mitigate|disconnect|continue
FROM python:3.12-alpine
RUN apk add --no-cache iproute2 wireguard-tools
WORKDIR /opt/tvv
COPY pyproject.toml README.md ./
COPY tunnelvisionvision ./tunnelvisionvision
RUN pip install --no-cache-dir . && rm -rf /root/.cache
ENTRYPOINT ["tvv"]
CMD ["daemon"]
