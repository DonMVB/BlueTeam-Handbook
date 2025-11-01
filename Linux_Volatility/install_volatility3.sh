#!/bin/bash

# Volatility 3 Installation Script for Ubuntu 24.04 LTS
# This script installs Volatility 3 framework with all dependencies
# and configures it to work in /cases directory structure

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CASES_DIR="/cases"
VOLATILITY_DIR="$CASES_DIR/volatility3"
TEMP_DIR="$CASES_DIR/temp"
SYMBOLS_DIR="$VOLATILITY_DIR/symbols"
VENV_DIR="$VOLATILITY_DIR/venv"

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

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Function to check Ubuntu version
check_ubuntu_version() {
    if ! lsb_release -d | grep -q "Ubuntu 24.04"; then
        print_warning "This script is designed for Ubuntu 24.04 LTS. Other versions may work but are not tested."
        read -p "Do you want to continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Function to create directory structure
create_directories() {
    print_status "Creating directory structure..."
    
    sudo mkdir -p "$CASES_DIR"
    sudo chown $(whoami):$(whoami) "$CASES_DIR"
    
    mkdir -p "$VOLATILITY_DIR"
    mkdir -p "$TEMP_DIR"
    mkdir -p "$SYMBOLS_DIR"
    
    print_success "Directory structure created"
}

# Function to install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    sudo apt update
    sudo apt install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        git \
        wget \
        curl \
        unzip \
        libssl-dev \
        libffi-dev \
        libyajl-dev \
        pkg-config
    
    print_success "System dependencies installed"
}

# Function to create Python virtual environment
create_venv() {
    print_status "Creating Python virtual environment..."
    
    cd "$VOLATILITY_DIR"
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip and setuptools
    pip install --upgrade pip setuptools wheel
    
    print_success "Virtual environment created"
}

# Function to install Volatility 3
install_volatility3() {
    print_status "Installing Volatility 3 from PyPI..."
    
    cd "$VOLATILITY_DIR"
    source venv/bin/activate
    
    # Install Volatility 3 with all optional dependencies
    pip install volatility3[complete]
    
    print_success "Volatility 3 installed"
}

# Function to download Windows symbol tables
download_symbols() {
    print_status "Downloading Windows symbol tables..."
    
    cd "$SYMBOLS_DIR"
    
    # Download Windows symbols
    print_status "Downloading Windows symbols pack..."
    wget -O windows.zip https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
    
    # Extract symbols
    print_status "Extracting Windows symbols..."
    unzip -q windows.zip
    rm windows.zip
    
    print_success "Windows symbol tables downloaded and extracted"
}

# Function to configure Volatility 3 environment
configure_volatility() {
    print_status "Configuring Volatility 3 environment..."
    
    # Create configuration file to set temp directory
    cat > "$VOLATILITY_DIR/volatility3.conf" << EOF
[volatility3]
# Volatility 3 Configuration File
# Set temporary directory
cache-dir = $TEMP_DIR
symbols-dir = $SYMBOLS_DIR
EOF
    
    # Create environment setup script
    cat > "$VOLATILITY_DIR/setup_env.sh" << 'EOF'
#!/bin/bash
# Volatility 3 Environment Setup Script

# Set environment variables
export VOLATILITY_CACHE_PATH="/cases/temp"
export VOLATILITY_SYMBOLS_PATH="/cases/volatility3/symbols"
export TMPDIR="/cases/temp"
export TMP="/cases/temp"
export TEMP="/cases/temp"

# Activate virtual environment
source /cases/volatility3/venv/bin/activate

# Add volatility3 to PATH if not already there
if [[ ":$PATH:" != *":/cases/volatility3/venv/bin:"* ]]; then
    export PATH="/cases/volatility3/venv/bin:$PATH"
fi

echo "Volatility 3 environment activated"
echo "Volatility 3 location: $(which vol)"
echo "Python version: $(python --version)"
echo "Volatility 3 version: $(vol --version 2>/dev/null || echo 'Run vol --version to check')"
EOF
    
    chmod +x "$VOLATILITY_DIR/setup_env.sh"
    
    # Create wrapper script for vol command
    cat > "$VOLATILITY_DIR/vol.sh" << EOF
#!/bin/bash
# Volatility 3 Wrapper Script

# Set environment variables for temp directories
export VOLATILITY_CACHE_PATH="$TEMP_DIR"
export VOLATILITY_SYMBOLS_PATH="$SYMBOLS_DIR"
export TMPDIR="$TEMP_DIR"
export TMP="$TEMP_DIR"
export TEMP="$TEMP_DIR"

# Activate virtual environment and run volatility
source "$VENV_DIR/bin/activate"
vol "\$@"
EOF
    
    chmod +x "$VOLATILITY_DIR/vol.sh"
    
    print_success "Volatility 3 configured"
}

# Function to create symbolic links
create_symlinks() {
    print_status "Creating symbolic links..."
    
    # Create symlink in /usr/local/bin for global access
    sudo ln -sf "$VOLATILITY_DIR/vol.sh" /usr/local/bin/vol3
    
    print_success "Symbolic links created (vol3 command available globally)"
}

# Function to test installation
test_installation() {
    print_status "Testing Volatility 3 installation..."
    
    cd "$VOLATILITY_DIR"
    source venv/bin/activate
    
    # Test basic functionality
    if vol --help > /dev/null 2>&1; then
        print_success "Volatility 3 help command works"
    else
        print_error "Volatility 3 help command failed"
        return 1
    fi
    
    # Test plugin listing
    if vol -h | grep -q "Choose a plugin to run"; then
        print_success "Volatility 3 plugins are accessible"
    else
        print_warning "Plugin listing may have issues"
    fi
    
    # Check symbols directory
    if [ -d "$SYMBOLS_DIR/windows" ]; then
        print_success "Windows symbols are available"
    else
        print_warning "Windows symbols directory not found"
    fi
    
    print_success "Installation test completed"
}

# Function to create usage documentation
create_documentation() {
    print_status "Creating usage documentation..."
    
    cat > "$VOLATILITY_DIR/README.md" << EOF
# Volatility 3 Installation

This installation of Volatility 3 is configured to work entirely within the /cases directory structure.

## Directory Structure
- **Installation**: $VOLATILITY_DIR
- **Symbols**: $SYMBOLS_DIR
- **Temporary files**: $TEMP_DIR
- **Virtual environment**: $VENV_DIR

## Usage

### Method 1: Using the global command
\`\`\`bash
vol3 -h
vol3 -f memory.dmp windows.info
\`\`\`

### Method 2: Using the environment setup script
\`\`\`bash
source $VOLATILITY_DIR/setup_env.sh
vol -f memory.dmp windows.info
\`\`\`

### Method 3: Direct activation
\`\`\`bash
cd $VOLATILITY_DIR
source venv/bin/activate
vol -f memory.dmp windows.info
\`\`\`

## Configuration
- Configuration file: $VOLATILITY_DIR/volatility3.conf
- Environment script: $VOLATILITY_DIR/setup_env.sh
- Wrapper script: $VOLATILITY_DIR/vol.sh

## Symbols
Windows symbols are automatically downloaded and stored in $SYMBOLS_DIR

## Temporary Files
All temporary files are stored in $TEMP_DIR to keep the home directory clean.

## Memory Analysis Workflow
1. Place memory dumps in $CASES_DIR
2. Use vol3 command or source the environment
3. Analyze memory dumps with Volatility 3
4. Results and temporary files stay within /cases structure

## Example Commands
\`\`\`bash
# Get basic system info
vol3 -f /cases/memory.dmp windows.info

# List processes
vol3 -f /cases/memory.dmp windows.pslist

# Show network connections
vol3 -f /cases/memory.dmp windows.netscan

# Extract process
vol3 -f /cases/memory.dmp -o /cases/output windows.memmap --pid 1234 --dump
\`\`\`
EOF
    
    print_success "Documentation created at $VOLATILITY_DIR/README.md"
}

# Function to display final information
display_final_info() {
    echo
    print_success "Volatility 3 installation completed successfully!"
    echo
    echo "Installation Details:"
    echo "- Volatility 3 installed in: $VOLATILITY_DIR"
    echo "- Virtual environment: $VENV_DIR"
    echo "- Symbols directory: $SYMBOLS_DIR"
    echo "- Temporary files: $TEMP_DIR"
    echo "- Global command: vol3"
    echo
    echo "Quick Start:"
    echo "1. Place your memory dump in $CASES_DIR"
    echo "2. Run: vol3 -f /cases/your_memory_dump.dmp windows.info"
    echo
    echo "For detailed usage information, see: $VOLATILITY_DIR/README.md"
    echo
    print_warning "Note: Make sure to set appropriate permissions on $CASES_DIR if multiple users need access"
}

# Main execution
main() {
    echo "Volatility 3 Installation Script for Ubuntu 24.04 LTS"
    echo "======================================================"
    echo
    
    check_root
    check_ubuntu_version
    
    print_status "Starting Volatility 3 installation..."
    
    create_directories
    install_system_deps
    create_venv
    install_volatility3
    download_symbols
    configure_volatility
    create_symlinks
    test_installation
    create_documentation
    
    display_final_info
}

# Run main function
main "$@"
