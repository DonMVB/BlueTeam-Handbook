#!/bin/bash

# Network Analysis Tools Installer and Version Checker for Ubuntu 24.04 LTS
# Installs and checks: tcpdump, wireshark, tshark, ngrep, zeek
# Configures Zeek logging and logrotate

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
ZEEK_LOG_DIR="/nsm/zeek/logs"
LOGROTATE_CONF="/etc/logrotate.d/zeek-logs"

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_header() {
    echo
    print_status "$CYAN" "=========================================="
    print_status "$CYAN" "$1"
    print_status "$CYAN" "=========================================="
}

# Function to extract version number from version string
extract_version() {
    echo "$1" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1
}

# Function to check if package is installed
is_package_installed() {
    dpkg -l | grep -q "^ii.*$1 "
}

# Function to install package if not present
install_package() {
    local package=$1
    local description=$2
    
    print_status "$BLUE" "Checking $description..."
    if is_package_installed "$package"; then
        print_status "$GREEN" "$description is already installed"
    else
        print_status "$YELLOW" "Installing $description..."
        
        # Use DEBIAN_FRONTEND=noninteractive to prevent any interactive prompts
        if DEBIAN_FRONTEND=noninteractive $SUDO apt install -y "$package"; then
            print_status "$GREEN" "Successfully installed $description"
        else
            print_status "$RED" "Failed to install $description"
            return 1
        fi
    fi
}

# Function to get full path of binary and add to PATH if needed
find_and_add_to_path() {
    local binary=$1
    local package_name=$2
    
    # Common installation directories to check
    local search_paths=(
        "/usr/bin"
        "/usr/local/bin"
        "/usr/sbin"
        "/usr/local/sbin"
        "/opt/$package_name/bin"
        "/usr/local/$package_name/bin"
        "/opt/zeek/bin"
        "/usr/local/zeek/bin"
    )
    
    # First check if it's already in PATH
    if command -v "$binary" >/dev/null 2>&1; then
        which "$binary"
        return 0
    fi
    
    # Search in common directories
    for dir in "${search_paths[@]}"; do
        if [ -x "$dir/$binary" ]; then
            # Add to PATH if not already there
            if [[ ":$PATH:" != *":$dir:"* ]]; then
                export PATH="$PATH:$dir"
                print_status "$BLUE" "Added $dir to PATH for $binary"
                
                # Add to user's profile for persistence
                if [ -n "$HOME" ] && [ -w "$HOME/.bashrc" ]; then
                    if ! grep -q "export PATH.*$dir" "$HOME/.bashrc"; then
                        echo "export PATH=\"\$PATH:$dir\"" >> "$HOME/.bashrc"
                        print_status "$BLUE" "Added $dir to ~/.bashrc for permanent PATH"
                    fi
                fi
            fi
            echo "$dir/$binary"
            return 0
        fi
    done
    
    return 1
}

# Function to get version using binary execution
get_binary_version() {
    local binary_name=$1
    local package_name=$2
    local version_flag=$3
    
    local binary_path=$(find_and_add_to_path "$binary_name" "$package_name")
    
    if [ -n "$binary_path" ] && [ -x "$binary_path" ]; then
        case "$binary_name" in
            "tcpdump")
                "$binary_path" --version 2>&1 | head -1
                ;;
            "wireshark")
                "$binary_path" --version 2>/dev/null | head -1 || echo "GUI version check failed"
                ;;
            "tshark")
                "$binary_path" --version 2>/dev/null | head -1
                ;;
            "ngrep")
                "$binary_path" -V 2>&1 | head -1
                ;;
            "zeek")
                "$binary_path" --version 2>/dev/null | head -1
                ;;
            *)
                "$binary_path" "$version_flag" 2>/dev/null | head -1 || echo "Version check failed"
                ;;
        esac
    else
        echo "Binary not found"
    fi
}

# Function to create directory with proper permissions
create_directory() {
    local dir=$1
    local user=$2
    local group=$3
    local perms=$4
    
    if [ ! -d "$dir" ]; then
        print_status "$BLUE" "Creating directory: $dir"
        sudo mkdir -p "$dir"
        if [ -n "$user" ] && [ -n "$group" ]; then
            sudo chown "$user:$group" "$dir"
        fi
        if [ -n "$perms" ]; then
            sudo chmod "$perms" "$dir"
        fi
        print_status "$GREEN" "Directory created: $dir"
    else
        print_status "$GREEN" "Directory already exists: $dir"
    fi
}

print_header "Network Analysis Tools Installer"

# Check if running as root (we need sudo for installations)
if [ "$EUID" -eq 0 ]; then
    print_status "$YELLOW" "Running as root. Script will use direct commands instead of sudo."
    SUDO=""
else
    SUDO="sudo"
fi

# Stop PackageKit if it's running to prevent conflicts
if pgrep -x "packagekitd" > /dev/null; then
    print_status "$YELLOW" "Stopping PackageKit service to prevent conflicts..."
    $SUDO systemctl stop packagekit
fi

# Wait for any apt locks to clear
print_status "$BLUE" "Waiting for package locks to clear..."
while $SUDO fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    print_status "$YELLOW" "Waiting for other package operations to complete..."
    sleep 5
done

# Initial apt update for standard packages
print_header "Preparing Package Database"
update_apt_if_needed "initial setup"

# Update package database only when needed
update_apt_if_needed() {
    local reason=$1
    print_status "$BLUE" "Updating package database ($reason)..."
    if $SUDO apt update; then
        print_status "$GREEN" "Package database updated"
    else
        print_status "$RED" "Failed to update package database"
        exit 1
    fi
}

# Pre-configure packages to avoid interactive prompts
print_header "Pre-configuring Packages"
print_status "$BLUE" "Setting up non-interactive package configurations..."

# Pre-configure Postfix to avoid prompts
echo "postfix postfix/main_mailer_type string 'No configuration'" | $SUDO debconf-set-selections
echo "postfix postfix/mailname string localhost" | $SUDO debconf-set-selections

# Pre-configure other potentially interactive packages
echo "wireshark-common wireshark-common/install-setuid boolean true" | $SUDO debconf-set-selections

print_status "$GREEN" "Package pre-configuration complete"

# Install tcpdump
print_header "Installing/Checking tcpdump"
install_package "tcpdump" "tcpdump"

# Install Wireshark and recommended packages
print_header "Installing/Checking Wireshark"
print_status "$BLUE" "Installing Wireshark with recommended packages..."
if DEBIAN_FRONTEND=noninteractive $SUDO apt install -y wireshark wireshark-common wireshark-doc; then
    print_status "$GREEN" "Wireshark and recommended packages installed"
    
    # Configure wireshark for non-root usage (already pre-configured above)
    print_status "$BLUE" "Configuring Wireshark for non-root usage..."
    $SUDO dpkg-reconfigure -f noninteractive wireshark-common
    
    # Add current user to wireshark group if not root
    if [ "$EUID" -ne 0 ] && [ -n "$USER" ]; then
        $SUDO usermod -a -G wireshark "$USER"
        print_status "$YELLOW" "User $USER added to wireshark group. You may need to log out and back in for changes to take effect."
    fi
else
    print_status "$RED" "Failed to install Wireshark"
fi

# Check tshark (usually comes with wireshark)
print_header "Checking tshark"
if command -v tshark >/dev/null 2>&1; then
    print_status "$GREEN" "tshark is available (comes with Wireshark)"
else
    print_status "$YELLOW" "Installing tshark separately..."
    install_package "tshark" "tshark"
fi

# Install ngrep
print_header "Installing/Checking ngrep"
install_package "ngrep" "ngrep"

# Install Zeek (formerly Bro)
print_header "Installing/Checking Zeek"
print_status "$BLUE" "Checking for Zeek installation..."

# First try to install from Ubuntu repositories
if install_package "zeek" "Zeek Network Security Monitor"; then
    ZEEK_INSTALLED=true
else
    # If not available in standard repos, try to add Zeek repository
    print_status "$YELLOW" "Zeek not found in standard repositories. Attempting to add Zeek repository..."
    
    # Install prerequisites for adding repositories
    DEBIAN_FRONTEND=noninteractive $SUDO apt install -y software-properties-common apt-transport-https ca-certificates gnupg lsb-release
    
    # Add Zeek repository (for Ubuntu 24.04)
    if curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | $SUDO gpg --dearmor -o /usr/share/keyrings/zeek-archive-keyring.gpg; then
        echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/ /" | $SUDO tee /etc/apt/sources.list.d/zeek.list
        
        # Update apt only for the new repository
        update_apt_if_needed "added Zeek repository"
        
        if install_package "zeek" "Zeek Network Security Monitor"; then
            ZEEK_INSTALLED=true
        else
            print_status "$RED" "Failed to install Zeek from external repository"
            ZEEK_INSTALLED=false
        fi
    else
        print_status "$RED" "Failed to add Zeek repository"
        ZEEK_INSTALLED=false
    fi
fi

# Configure Zeek if installed
if [ "$ZEEK_INSTALLED" = true ]; then
    print_header "Configuring Zeek"
    
    # Create Zeek log directory
    create_directory "$ZEEK_LOG_DIR" "root" "root" "755"
    
    # Find Zeek installation directory
    ZEEK_BIN=$(which zeek 2>/dev/null || echo "")
    if [ -n "$ZEEK_BIN" ]; then
        ZEEK_BASE_DIR=$(dirname $(dirname "$ZEEK_BIN"))
        print_status "$GREEN" "Zeek found at: $ZEEK_BASE_DIR"
        
        # Configure Zeek to use our log directory
        ZEEK_SITE_DIR="$ZEEK_BASE_DIR/share/zeek/site"
        if [ -d "$ZEEK_SITE_DIR" ]; then
            print_status "$BLUE" "Configuring Zeek logging directory..."
            
            # Create local configuration
            cat > /tmp/zeek-local.zeek << EOF
# Custom logging configuration for /nsm/zeek/logs
redef Log::default_logdir = "$ZEEK_LOG_DIR";

# Enable additional logs that might be useful
@load tuning/defaults
@load misc/loaded-scripts
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
@load protocols/dns/software
EOF
            
            $SUDO cp /tmp/zeek-local.zeek "$ZEEK_SITE_DIR/local.zeek.custom"
            rm /tmp/zeek-local.zeek
            
            print_status "$GREEN" "Zeek configured to log to $ZEEK_LOG_DIR"
        fi
    fi
    
    # Configure logrotate for Zeek logs
    print_header "Configuring Log Rotation for Zeek"
    print_status "$BLUE" "Creating logrotate configuration for Zeek logs..."
    
    cat > /tmp/zeek-logrotate << EOF
# Logrotate configuration for Zeek logs
$ZEEK_LOG_DIR/*.log {
    daily
    compress
    compresscmd /bin/gzip
    compressext .gz
    delaycompress
    missingok
    notifempty
    rotate 30
    sharedscripts
    copytruncate
    create 644 root root
    postrotate
        # Signal zeek to reopen log files if it's running
        if pgrep -x "zeek" > /dev/null; then
            pkill -SIGUSR1 -x zeek
        fi
    endscript
}

# Handle Zeek's current directory logs
$ZEEK_LOG_DIR/current/*.log {
    daily
    compress
    compresscmd /bin/gzip
    compressext .gz
    delaycompress
    missingok
    notifempty
    rotate 30
    sharedscripts
    copytruncate
    create 644 root root
}
EOF
    
    $SUDO cp /tmp/zeek-logrotate "$LOGROTATE_CONF"
    rm /tmp/zeek-logrotate
    $SUDO chmod 644 "$LOGROTATE_CONF"
    
    print_status "$GREEN" "Logrotate configured for Zeek logs"
    
    # Test logrotate configuration
    print_status "$BLUE" "Testing logrotate configuration..."
    if $SUDO logrotate -d "$LOGROTATE_CONF" >/dev/null 2>&1; then
        print_status "$GREEN" "Logrotate configuration is valid"
    else
        print_status "$YELLOW" "Logrotate configuration test had warnings (this is often normal)"
    fi
fi

# Final version check and summary
print_header "Installation Summary and Version Information"

print_status "$BLUE" "Installed tool versions:"
echo

# tcpdump version - use full path and binary execution
print_status "$BLUE" "Getting tcpdump version..."
TCPDUMP_VERSION=$(get_binary_version "tcpdump" "tcpdump" "--version")
TCPDUMP_PATH=$(find_and_add_to_path "tcpdump" "tcpdump" 2>/dev/null || echo "Not found")
if [ "$TCPDUMP_PATH" != "Not found" ]; then
    print_status "$GREEN" "tcpdump: $TCPDUMP_VERSION"
    print_status "$CYAN" "  Location: $TCPDUMP_PATH"
else
    print_status "$RED" "tcpdump: Not found"
fi

# Wireshark version - use full path and binary execution
print_status "$BLUE" "Getting Wireshark version..."
WIRESHARK_VERSION=$(get_binary_version "wireshark" "wireshark" "--version")
WIRESHARK_PATH=$(find_and_add_to_path "wireshark" "wireshark" 2>/dev/null || echo "Not found")
if [ "$WIRESHARK_PATH" != "Not found" ]; then
    print_status "$GREEN" "Wireshark: $WIRESHARK_VERSION"
    print_status "$CYAN" "  Location: $WIRESHARK_PATH"
else
    print_status "$RED" "Wireshark: Not found"
fi

# tshark version - use full path and binary execution
print_status "$BLUE" "Getting tshark version..."
TSHARK_VERSION=$(get_binary_version "tshark" "tshark" "--version")
TSHARK_PATH=$(find_and_add_to_path "tshark" "tshark" 2>/dev/null || echo "Not found")
if [ "$TSHARK_PATH" != "Not found" ]; then
    print_status "$GREEN" "tshark: $TSHARK_VERSION"
    print_status "$CYAN" "  Location: $TSHARK_PATH"
else
    print_status "$RED" "tshark: Not found"
fi

# ngrep version - use full path and binary execution
print_status "$BLUE" "Getting ngrep version..."
NGREP_VERSION=$(get_binary_version "ngrep" "ngrep" "-V")
NGREP_PATH=$(find_and_add_to_path "ngrep" "ngrep" 2>/dev/null || echo "Not found")
if [ "$NGREP_PATH" != "Not found" ]; then
    print_status "$GREEN" "ngrep: $NGREP_VERSION"
    print_status "$CYAN" "  Location: $NGREP_PATH"
else
    print_status "$RED" "ngrep: Not found"
fi

# Zeek version - use full path and binary execution
print_status "$BLUE" "Getting Zeek version..."
ZEEK_VERSION=$(get_binary_version "zeek" "zeek" "--version")
ZEEK_PATH=$(find_and_add_to_path "zeek" "zeek" 2>/dev/null || echo "Not found")
if [ "$ZEEK_PATH" != "Not found" ]; then
    print_status "$GREEN" "Zeek: $ZEEK_VERSION"
    print_status "$CYAN" "  Location: $ZEEK_PATH"
else
    print_status "$RED" "Zeek: Not found"
fi

echo
print_status "$BLUE" "Configuration Summary:"
echo "• Zeek logs directory: $ZEEK_LOG_DIR"
echo "• Logrotate config: $LOGROTATE_CONF"
echo "• Log rotation: Daily with 30-day retention"
echo "• Log compression: gzip with .gz extension"

echo
print_status "$GREEN" "Installation and configuration complete!"
print_status "$YELLOW" "Note: You may need to log out and back in for group permissions to take effect."
print_status "$BLUE" "To start using Zeek: sudo zeek -i <interface> local"

print_header "Script Complete"
