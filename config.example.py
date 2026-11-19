"""
config.example.py - Copy this file to config.py and fill in your own values.

config.py is git-ignored, so your environment details never reach the repo.
"""

# Name of the network interface to scan from.
# Find yours with:
#     python -c "from scapy.all import conf; print(conf.ifaces)"
INTERFACE = "YOUR-NETWORK-INTERFACE-NAME"

# Network range(s) to scan, in CIDR notation.
# ARP cannot cross subnets, so list only networks this machine is joined to.
TARGETS = ["192.168.1.0/24"]

# Seconds to wait for ARP replies before giving up.
SCAN_TIMEOUT = 5