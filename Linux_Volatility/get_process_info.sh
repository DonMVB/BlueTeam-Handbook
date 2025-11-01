#!/bin/bash

# Process Information Gathering Script for Incident Response
# Iterates through /proc filesystem to collect process details

echo "=== Process Information Collection ==="
echo "Timestamp: $(date)"
echo "Hostname: $(hostname)"
echo "======================================"
echo

# Function to safely read proc files (they may disappear or be inaccessible)
safe_read() {
    local file="$1"
    if [[ -r "$file" ]]; then
        cat "$file" 2>/dev/null
    else
        echo "[INACCESSIBLE]"
    fi
}

# Function to get process owner
get_process_owner() {
    local pid="$1"
    local stat_file="/proc/$pid/status"
    if [[ -r "$stat_file" ]]; then
        local uid=$(grep "^Uid:" "$stat_file" 2>/dev/null | awk '{print $2}')
        if [[ -n "$uid" ]]; then
            getent passwd "$uid" 2>/dev/null | cut -d: -f1 || echo "UID:$uid"
        else
            echo "[UNKNOWN]"
        fi
    else
        echo "[UNKNOWN]"
    fi
}

# Header for tab-separated output
printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "PID" "OWNER" "EXE" "CWD" "CMDLINE" "ENVIRONMENT" "SUSPICIOUS_INDICATORS"

# Iterate through all numeric directories in /proc
for pid_dir in /proc/[0-9]*; do
    # Extract PID from directory name
    pid=$(basename "$pid_dir")
    
    # Skip if not a valid PID directory
    [[ ! -d "$pid_dir" ]] && continue
    
    # Initialize variables
    exe="[UNKNOWN]"
    cwd="[UNKNOWN]"
    cmdline="[UNKNOWN]"
    environment="[UNKNOWN]"
    owner="[UNKNOWN]"
    suspicious=""
    
    # Get process owner
    owner=$(get_process_owner "$pid")
    
    # Get executable path (full path, no truncation)
    if [[ -L "$pid_dir/exe" ]]; then
        exe=$(readlink "$pid_dir/exe" 2>/dev/null || echo "[DELETED]")
    fi
    
    # Get current working directory (full path, no truncation)
    if [[ -L "$pid_dir/cwd" ]]; then
        cwd=$(readlink "$pid_dir/cwd" 2>/dev/null || echo "[DELETED]")
    fi
    
    # Get command line (full command line, no truncation)
    if [[ -r "$pid_dir/cmdline" ]]; then
        # Replace null bytes with spaces
        cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null | sed 's/[[:space:]]*$//')
        [[ -z "$cmdline" ]] && cmdline="[KERNEL_THREAD]"
    fi
    
    # Get environment variables
    if [[ -r "$pid_dir/environ" ]]; then
        # Convert null-separated environment to semicolon-separated to avoid tab conflicts
        environment=$(tr '\0' ';' < "$pid_dir/environ" 2>/dev/null | sed 's/;$//')
        [[ -z "$environment" ]] && environment="[EMPTY]"
    fi
    
    # Check for suspicious indicators
    suspicious_flags=()
    
    # Check if running from tmp directories
    if [[ "$exe" == *"/tmp/"* ]] || [[ "$exe" == *"/var/tmp/"* ]] || [[ "$cwd" == *"/tmp"* ]]; then
        suspicious_flags+=("TMP_DIR")
    fi
    
    # Check if deleted executable
    if [[ "$exe" == *"(deleted)"* ]] || [[ "$exe" == "[DELETED]" ]]; then
        suspicious_flags+=("DELETED_EXE")
    fi
    
    # Check for hidden processes (unusual for legitimate processes)
    if [[ "$exe" == .*/* ]]; then
        suspicious_flags+=("HIDDEN")
    fi
    
    # Check for processes with suspicious environment variables
    if [[ "$environment" == *"LD_PRELOAD"* ]] || [[ "$environment" == *"LD_LIBRARY_PATH"* ]]; then
        suspicious_flags+=("SUSP_ENV")
    fi
    
    # Check for processes with unusual names or paths
    if [[ "$cmdline" == *"base64"* ]] || [[ "$cmdline" == *"curl"* ]] || [[ "$cmdline" == *"wget"* ]]; then
        suspicious_flags+=("NET_TOOLS")
    fi
    
    # Join suspicious flags with semicolons to avoid tab conflicts
    if [[ ${#suspicious_flags[@]} -gt 0 ]]; then
        suspicious=$(IFS=';'; echo "${suspicious_flags[*]}")
    fi
    
    # Output tab-separated values
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$pid" "$owner" "$exe" "$cwd" "$cmdline" "$environment" "$suspicious"
done

echo
echo "=== Detailed Analysis Available ==="
echo "For detailed analysis of a specific PID, use:"
echo "  cat /proc/PID/environ | tr '\\0' '\\n'    # Environment variables"
echo "  cat /proc/PID/cmdline | tr '\\0' ' '     # Full command line"
echo "  ls -la /proc/PID/fd/                     # File descriptors"
echo "  cat /proc/PID/maps                       # Memory mappings"
echo "  cat /proc/PID/status                     # Process status"
