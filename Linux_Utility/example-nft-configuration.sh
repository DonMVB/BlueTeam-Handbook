#!/bin/bash     
# On systemd systems:
#    systemctl {start|stop|restart|status} nftables
#    nft list ruleset > /etc/nftables.conf
#    nft -f /etc/nftables.conf
# For connection tracking modules, add to /etc/modules-load.d/nftables.conf:
#    nf_conntrack
#    nf_conntrack_ftp
#    nf_conntrack_netbios_ns
#
# Modern path handling
PATH=/usr/sbin:/sbin:/usr/bin:/bin
export PATH
# Check if nft is available
if ! command -v nft &> /dev/null; then
    echo "Error: nftables (nft) is not installed or not in PATH"
    echo "Install with: apt install nftables (Debian/Ubuntu) or dnf install nftables (RHEL/Fedora)"
    exit 1
fi
# Flush existing rules and delete all tables
echo "Flushing existing nftables rules..."
nft flush ruleset
# Create inet table (handles both IPv4 and IPv6)
echo "Creating nft FW table and chains"
nft add table inet filter
# Create base chains with default policies
# Input chain - default drop policy
nft add chain inet filter input { type filter hook input priority filter \; policy drop \; }
# Output chain set to default drop policy  
nft add chain inet filter output { type filter hook output priority filter \; policy drop \; }
# Forward chain set to default drop policy
nft add chain inet filter forward { type filter hook forward priority filter \; policy drop \; }
echo "Setting up loopback interface rules."
# Allow loopback traffic
nft add rule inet filter input iif lo accept
nft add rule inet filter output oif lo accept
# Drop traffic from 127.0.0.0/8 that doesn't use loopback interface
nft add rule inet filter input ip saddr 127.0.0.0/8 iif != lo drop
nft add rule inet filter input ip6 saddr ::1 iif != lo drop
echo "Setting up connection tracking rules."
# Allow established and related connections (both inbound and outbound)
nft add rule inet filter input ct state established,related accept
nft add rule inet filter output ct state established,related accept
echo "Setting up inbound service rules for specific network and specific source Ips."
# SSH access restricted to specific sources only
nft add rule inet filter input ip saddr 10.110.0.0/16 tcp dport 22 ct state new accept
nft add rule inet filter input ip saddr { 192.168.44.36, 192.168.44.37 } tcp dport 22 ct state new accept
# Allow inbound SSH connections (port 22)
# nft add rule inet filter input tcp dport 22 ct state new accept
# Allow inbound ICMP (ping responses, etc.)
nft add rule inet filter input ip protocol icmp accept
nft add rule inet filter input ip6 nexthdr icmpv6 accept
echo "Setting up outbound traffic rules..."
# Allow all new outbound connections
nft add rule inet filter output ct state new,established accept
# Alternative: More restrictive outbound rules (uncomment if needed)
# nft add rule inet filter output tcp dport { 22, 53, 80, 443, 123 } ct state new accept  # SSH, DNS, HTTP/HTTPS, NTP
# nft add rule inet filter output udp dport { 53, 123 } ct state new accept              # DNS, NTP
echo "Setting up logging for dropped packets..."
# Log dropped packets (rate limited to prevent log flooding)
nft add rule inet filter input limit rate 5/minute log prefix \"NFT-INPUT-DROP: \" level warn
nft add rule inet filter output limit rate 5/minute log prefix \"NFT-OUTPUT-DROP: \" level warn  
nft add rule inet filter forward limit rate 5/minute log prefix \"NFT-FORWARD-DROP: \" level warn
echo "Firewall rules applied"
echo "Current ruleset:"
nft list ruleset
echo "To save current rules:"
echo "  nft list ruleset > /etc/nftables.conf"
echo "To restore rules:"
echo "  nft -f /etc/nftables.conf"
echo "To enable nftables service at boot:"
echo "  systemctl enable nftables"
# Optional: Save rules automatically
read -p "Save current rules to /etc/nftables.conf? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    nft list ruleset > /etc/nftables.conf
    echo "Rules saved to /etc/nftables.conf"
    
    # Enable service if systemd is available
    if command -v systemctl &> /dev/null; then
        systemctl enable nftables
        echo "nftables service enabled for boot"
    fi
fi
