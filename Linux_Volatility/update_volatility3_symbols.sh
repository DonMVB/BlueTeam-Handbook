#!/bin/bash

# Updated Volatility 3 Windows Symbol Tables Script
# This script downloads the most current Windows symbol tables from multiple sources
# including JPCERTCC which has more comprehensive Windows 11 support
# Copyright 2025 Don Murdoch, Blue Team Handbook

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
SYMBOLS_DIR="$VOLATILITY_DIR/symbols"
BACKUP_DIR="$SYMBOLS_DIR/backup_$(date +%Y%m%d_%H%M%S)"

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

# Function to check if directories exist
check_installation() {
    if [ ! -d "$VOLATILITY_DIR" ]; then
        print_error "Volatility 3 installation not found at $VOLATILITY_DIR"
        print_error "Please run the main installation script first"
        exit 1
    fi
    
    if [ ! -d "$SYMBOLS_DIR" ]; then
        print_status "Creating symbols directory..."
        mkdir -p "$SYMBOLS_DIR"
    fi
}

# Function to backup existing symbols
backup_existing_symbols() {
    if [ -d "$SYMBOLS_DIR/windows" ] || [ -f "$SYMBOLS_DIR"/*.zip ]; then
        print_status "Backing up existing symbols to $BACKUP_DIR"
        mkdir -p "$BACKUP_DIR"
        cp -r "$SYMBOLS_DIR"/* "$BACKUP_DIR"/ 2>/dev/null || true
        print_success "Existing symbols backed up"
    fi
}

# Function to clean old symbols
clean_old_symbols() {
    print_status "Cleaning old symbol files..."
    rm -rf "$SYMBOLS_DIR"/windows* 2>/dev/null || true
    rm -f "$SYMBOLS_DIR"/*.zip 2>/dev/null || true
    print_success "Old symbols cleaned"
}

# Function to download official Volatility Foundation symbols
download_official_symbols() {
    print_status "Downloading official Volatility Foundation Windows symbols..."
    
    cd "$SYMBOLS_DIR"
    
    # Download the main Windows symbols pack
    wget -O windows_official.zip "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip" || {
        print_warning "Failed to download official symbols, continuing with other sources..."
        return 1
    }
    
    # Extract official symbols
    unzip -q windows_official.zip
    rm windows_official.zip
    
    print_success "Official Volatility Foundation symbols downloaded"
}

# Function to download JPCERTCC symbols (more comprehensive Windows 11 support)
download_jpcertcc_symbols() {
    print_status "Downloading JPCERTCC Windows Symbol Tables (enhanced Windows 11 support)..."
    
    cd "$SYMBOLS_DIR"
    
    # Clone or download the JPCERTCC repository
    if command -v git &> /dev/null; then
        print_status "Using git to clone JPCERTCC symbol repository..."
        git clone --depth 1 https://github.com/JPCERTCC/Windows-Symbol-Tables.git jpcertcc_temp || {
            print_warning "Git clone failed, trying direct download..."
            download_jpcertcc_direct
            return $?
        }
        
        # Copy symbols from the repository
        if [ -d "jpcertcc_temp/symbols" ]; then
            cp -r jpcertcc_temp/symbols/* . 2>/dev/null || true
        fi
        
        # Clean up
        rm -rf jpcertcc_temp
        
    else
        download_jpcertcc_direct
    fi
    
    print_success "JPCERTCC symbols downloaded"
}

# Function to download JPCERTCC symbols directly
download_jpcertcc_direct() {
    print_status "Downloading JPCERTCC symbols via direct download..."
    
    # Download the repository as ZIP
    wget -O jpcertcc.zip "https://github.com/JPCERTCC/Windows-Symbol-Tables/archive/refs/heads/main.zip" || {
        print_warning "Failed to download JPCERTCC symbols"
        return 1
    }
    
    # Extract and copy symbols
    unzip -q jpcertcc.zip
    if [ -d "Windows-Symbol-Tables-main/symbols" ]; then
        cp -r Windows-Symbol-Tables-main/symbols/* . 2>/dev/null || true
    fi
    
    # Clean up
    rm -rf Windows-Symbol-Tables-main jpcertcc.zip
}

# Function to download additional Windows 11 specific symbols
download_additional_symbols() {
    print_status "Attempting to download additional Windows 11 symbols..."
    
    cd "$SYMBOLS_DIR"
    
    # Try to get the latest symbol list
    wget -O symbol_list.txt "https://downloads.volatilityfoundation.org/volatility3/symbols/MD5SUMS" 2>/dev/null || {
        print_warning "Could not download symbol list"
        return 1
    }
    
    # Look for any additional Windows symbol files
    grep -i "windows.*\.zip" symbol_list.txt | while read line; do
        filename=$(echo "$line" | awk '{print $2}')
        if [ "$filename" != "windows.zip" ] && [ ! -f "$filename" ]; then
            print_status "Downloading additional symbol file: $filename"
            wget -O "$filename" "https://downloads.volatilityfoundation.org/volatility3/symbols/$filename" || continue
            unzip -q "$filename" && rm "$filename"
        fi
    done
    
    rm -f symbol_list.txt
}

# Function to organize symbols
organize_symbols() {
    print_status "Organizing symbol files..."
    
    cd "$SYMBOLS_DIR"
    
    # Count symbol files
    json_count=$(find . -name "*.json" -type f | wc -l)
    zip_count=$(find . -name "*.zip" -type f | wc -l)
    
    print_status "Found $json_count JSON symbol files and $zip_count ZIP archives"
    
    # Create organized structure if needed
    if [ ! -d "windows" ] && [ $json_count -gt 0 ]; then
        mkdir -p windows
        find . -maxdepth 1 -name "*.json" -exec mv {} windows/ \;
        print_status "Organized loose JSON files into windows directory"
    fi
}

# Function to test symbol availability
test_symbols() {
    print_status "Testing symbol availability..."
    
    cd "$VOLATILITY_DIR"
    source venv/bin/activate
    
    # List available symbols
    print_status "Available symbol tables:"
    if [ -d "$SYMBOLS_DIR/windows" ]; then
        ls -la "$SYMBOLS_DIR/windows" | head -10
        symbol_count=$(ls -1 "$SYMBOLS_DIR/windows"/*.json 2>/dev/null | wc -l)
        print_success "Found $symbol_count Windows symbol files"
    else
        print_warning "No organized windows symbol directory found"
    fi
    
    # Test with a simple command (this will show if symbols load properly)
    print_status "Testing symbol loading (this may take a moment)..."
    timeout 30 vol windows.info --help > /dev/null 2>&1 && {
        print_success "Symbol loading test passed"
    } || {
        print_warning "Symbol loading test timed out or failed - this may be normal"
    }
}

# Function to create symbol update script for future use
create_update_script() {
    print_status "Creating symbol update script for future use..."
    
    cat > "$VOLATILITY_DIR/update_symbols.sh" << 'EOF'
#!/bin/bash
# Quick symbol update script
# Run this periodically to get the latest Windows symbols

SYMBOLS_DIR="/cases/volatility3/symbols"
BACKUP_DIR="$SYMBOLS_DIR/backup_$(date +%Y%m%d_%H%M%S)"

echo "Updating Windows symbols for Volatility 3..."

# Backup existing symbols
if [ -d "$SYMBOLS_DIR/windows" ]; then
    mkdir -p "$BACKUP_DIR"
    cp -r "$SYMBOLS_DIR"/* "$BACKUP_DIR"/ 2>/dev/null || true
    echo "Backed up existing symbols"
fi

cd "$SYMBOLS_DIR"

# Download latest JPCERTCC symbols
echo "Downloading latest JPCERTCC symbols..."
rm -rf jpcertcc_temp
git clone --depth 1 https://github.com/JPCERTCC/Windows-Symbol-Tables.git jpcertcc_temp
if [ -d "jpcertcc_temp/symbols" ]; then
    cp -r jpcertcc_temp/symbols/* . 2>/dev/null || true
fi
rm -rf jpcertcc_temp

# Download official symbols
echo "Downloading official Volatility symbols..."
wget -O windows_new.zip "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"
unzip -q windows_new.zip
rm windows_new.zip

echo "Symbol update completed!"
EOF
    
    chmod +x "$VOLATILITY_DIR/update_symbols.sh"
    print_success "Created $VOLATILITY_DIR/update_symbols.sh for future updates"
}

# Function to display troubleshooting information
display_troubleshooting() {
    echo
    print_status "Troubleshooting Information:"
    echo
    echo "If you still get symbol errors:"
    echo
    echo "1. Check your memory dump with 'file' command to identify the exact Windows version:"
    echo "   file /path/to/your/memory.dmp"
    echo
    echo "2. Try using the --symbol-dirs option to specify symbol directory:"
    echo "   vol3 -f memory.dmp --symbol-dirs $SYMBOLS_DIR windows.info"
    echo
    echo "3. Generate symbols from your memory dump:"
    echo "   vol3 -f memory.dmp isfinfo"
    echo "   # This will create ISF files that can be used as symbols"
    echo
    echo "4. Check available plugins and their requirements:"
    echo "   vol3 -f memory.dmp --list-plugins"
    echo
    echo "5. Use the banners.Banners plugin to identify the exact Windows build:"
    echo "   vol3 -f memory.dmp banners.Banners"
    echo
    echo "6. For Windows 11, try using windows.info.Info instead of just windows.info:"
    echo "   vol3 -f memory.dmp windows.info.Info"
    echo
    echo "Symbol directories:"
    echo "- Main symbols: $SYMBOLS_DIR"
    echo "- Backup: $BACKUP_DIR (if created)"
    echo
    echo "For the most current symbols, run: $VOLATILITY_DIR/update_symbols.sh"
}

# Main execution
main() {
    echo "Volatility 3 Windows Symbol Tables Update Script"
    echo "================================================"
    echo "This script downloads the most current Windows symbol tables"
    echo "including enhanced Windows 11 support from JPCERTCC"
    echo
    
    check_installation
    backup_existing_symbols
    clean_old_symbols
    
    print_status "Downloading symbol tables from multiple sources..."
    
    # Download from official source
    download_official_symbols
    
    # Download from JPCERTCC (better Windows 11 support)
    download_jpcertcc_symbols
    
    # Try to get additional symbols
    download_additional_symbols
    
    # Organize the symbols
    organize_symbols
    
    # Test the installation
    test_symbols
    
    # Create update script
    create_update_script
    
    print_success "Symbol update completed!"
    echo
    print_status "Summary:"
    echo "- Downloaded official Volatility Foundation symbols"
    echo "- Downloaded JPCERTCC symbols (enhanced Windows 11 support)"
    echo "- Symbols stored in: $SYMBOLS_DIR"
    echo "- Backup created in: $BACKUP_DIR (if applicable)"
    echo
    
    display_troubleshooting
}

# Run main function
main "$@"
