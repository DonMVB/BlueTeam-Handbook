#!/bin/bash

# Ubuntu 24.04.2 LTS Samba Server Setup Script
# This script installs Samba server/client, creates /cases directory, and configures sharing

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

print_status "Starting Ubuntu Samba Server Setup..."
print_status "System: Ubuntu 24.04.2 LTS"

# Step 1: Update system packages
print_status "Step 1: Updating system packages..."
apt update && apt upgrade -y
print_success "System packages updated"

# Step 2: Install Samba server and client components
print_status "Step 2: Installing Samba server and client components..."
apt install -y samba samba-common-bin smbclient cifs-utils
print_success "Samba components installed"

# Display installed Samba version
SAMBA_VERSION=$(smbd --version | cut -d' ' -f2)
print_success "Samba version installed: $SAMBA_VERSION"

# Step 3: Create /cases directory
print_status "Step 3: Creating /cases directory..."
if [ ! -d "/cases" ]; then
    mkdir -p /cases
    print_success "/cases directory created"
else
    print_warning "/cases directory already exists"
fi

# Set appropriate permissions for the cases directory
chown root:root /cases
chmod 755 /cases
print_success "Permissions set for /cases directory"

# Step 4: Backup original Samba configuration
print_status "Step 4: Backing up original Samba configuration..."
if [ -f "/etc/samba/smb.conf" ]; then
    cp /etc/samba/smb.conf /etc/samba/smb.conf.backup.$(date +%Y%m%d_%H%M%S)
    print_success "Original configuration backed up"
fi

# Step 5: Configure Samba share for /cases directory
print_status "Step 5: Configuring Samba share for /cases directory..."

# Create new smb.conf with cases share
cat > /etc/samba/smb.conf << 'EOF'
[global]
   workgroup = WORKGROUP
   server string = Ubuntu Samba Server
   netbios name = UBUNTU-SERVER
   security = user
   map to guest = bad user
   dns proxy = no
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   panic action = /usr/share/samba/panic-action %d

# Share for /cases directory
[cases]
   comment = Cases Directory Share
   path = /cases
   browseable = yes
   writable = yes
   guest ok = no
   read only = no
   create mask = 0755
   directory mask = 0755
   valid users = @sambausers
EOF

print_success "Samba configuration updated"

# Step 6: Create sambausers group
print_status "Step 6: Creating sambausers group..."
if ! getent group sambausers > /dev/null 2>&1; then
    groupadd sambausers
    print_success "sambausers group created"
else
    print_warning "sambausers group already exists"
fi

# Step 7: Test Samba configuration
print_status "Step 7: Testing Samba configuration..."
if testparm -s > /dev/null 2>&1; then
    print_success "Samba configuration is valid"
else
    print_error "Samba configuration has errors"
    testparm -s
    exit 1
fi

# Step 8: Enable and start Samba services
print_status "Step 8: Enabling and starting Samba services..."
systemctl enable smbd
systemctl enable nmbd
systemctl restart smbd
systemctl restart nmbd

# Check service status
if systemctl is-active --quiet smbd && systemctl is-active --quiet nmbd; then
    print_success "Samba services are running"
else
    print_error "Failed to start Samba services"
    systemctl status smbd
    systemctl status nmbd
    exit 1
fi

# Step 9: Configure firewall (if UFW is active)
print_status "Step 9: Configuring firewall..."
if ufw status | grep -q "Status: active"; then
    ufw allow samba
    print_success "Firewall configured for Samba"
else
    print_warning "UFW firewall is not active - skipping firewall configuration"
fi

# Step 10: Display setup summary
print_status "=== SETUP COMPLETE ==="
echo ""
print_success "Samba Server Setup Summary:"
echo "  • Samba version: $SAMBA_VERSION"
echo "  • Server components: smbd, nmbd"
echo "  • Client components: smbclient, cifs-utils"
echo "  • Cases directory: /cases"
echo "  • Share name: cases"
echo "  • Workgroup: WORKGROUP"
echo "  • Server name: UBUNTU-SERVER"
echo ""

print_status "Next Steps:"
echo "1. Create Samba users:"
echo "   sudo useradd -m <username>"
echo "   sudo usermod -aG sambausers <username>"
echo "   sudo smbpasswd -a <username>"
echo ""
echo "2. Test the share from a client:"
echo "   smbclient //$(hostname -I | awk '{print $1}')/cases -U <username>"
echo ""
echo "3. Mount from Linux client:"
echo "   sudo mount -t cifs //$(hostname -I | awk '{print $1}')/cases /mnt/cases -o username=<username>,uid=1000,gid=1000"
echo ""

print_status "Configuration files:"
echo "  • Main config: /etc/samba/smb.conf"
echo "  • Backup: /etc/samba/smb.conf.backup.*"
echo "  • Logs: /var/log/samba/"
echo ""

print_success "Samba setup completed successfully!"

# Display current share information
print_status "Current shares:"
smbclient -L localhost -N 2>/dev/null | grep -A 10 "Sharename"

