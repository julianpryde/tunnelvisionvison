"""TunnelVisionVision: endpoint detection and response for TunnelVision (CVE-2024-3661).

TunnelVision abuses DHCP option 121 (classless static routes, RFC 3442) to install
routes on a VPN client that are more specific than the VPN's own routes, so traffic
silently leaves via the physical interface instead of the tunnel.
"""

__version__ = "0.1.0"
