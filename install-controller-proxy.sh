#!/bin/bash

# JSON Proxy Service Installation Script
# This script installs and configures the JSON proxy service

# ChillXand Controller Version - Update this for each deployment
CHILLXAND_VERSION="v1.0.240"

# Define allowed IPs with descriptive names
declare -A ALLOWED_IPS=(
    ["74.208.234.116"]="Master USA"
    ["85.215.145.173"]="Control2 Germany" 
    ["194.164.163.124"]="Control3 Spain"
    ["174.114.192.84"]="Home"
    ["67.70.165.78"]="Home #2"
    ["127.0.0.1"]="Localhost"
)

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Update system and install dependencies
install_dependencies() {
    log "Updating system packages (excluding problematic repositories)..."
    
    # Create a temporary sources.list that excludes xandeum repository
    TEMP_SOURCES_DIR="/tmp/apt-sources-clean"
    mkdir -p "$TEMP_SOURCES_DIR"
    
    # Copy main sources.list
    cp /etc/apt/sources.list "$TEMP_SOURCES_DIR/"
    
    # Copy all sources.list.d files except xandeum ones
    if [[ -d "/etc/apt/sources.list.d" ]]; then
        mkdir -p "$TEMP_SOURCES_DIR/sources.list.d"
        for file in /etc/apt/sources.list.d/*; do
            if [[ -f "$file" ]] && ! grep -q "xandeum" "$file" 2>/dev/null; then
                cp "$file" "$TEMP_SOURCES_DIR/sources.list.d/"
            fi
        done
    fi
    
    # Function to run apt-get with clean sources
    run_clean_apt() {
        apt-get -o Dir::Etc::SourceList="$TEMP_SOURCES_DIR/sources.list" \
                -o Dir::Etc::SourceParts="$TEMP_SOURCES_DIR/sources.list.d" \
                "$@"
    }
    
    # Try updating with clean sources (no xandeum repo)
    if run_clean_apt update -qq; then
        log "Package lists updated successfully (excluding xandeum repository)"
    else
        warn "Clean apt-get update failed, trying fallback methods..."
        
        # Fallback 1: Try with original sources but suppress xandeum errors
        if apt-get update 2>&1 | grep -v "xandeum" | grep -q "Reading package lists"; then
            log "Package lists updated with warnings filtered"
        else
            warn "Standard apt-get update failed, trying with --allow-unauthenticated..."
            if apt-get update --allow-unauthenticated 2>&1 | grep -v "xandeum" | grep -q "Reading package lists"; then
                log "Package lists updated with --allow-unauthenticated (xandeum warnings filtered)"
            else
                warn "All apt-get update attempts failed, continuing anyway..."
                warn "Some packages may not be available or up to date"
            fi
        fi
    fi

    log "Installing required packages..."
    
    # Install packages using clean sources first, then fallback to regular
    for package in ufw python3 python3-pip net-tools curl; do
        log "Installing $package..."
        
        # Try with clean sources first
        if run_clean_apt install -y -qq "$package"; then
            log "Successfully installed $package (clean sources)"
        elif apt-get install -y -qq "$package"; then
            log "Successfully installed $package (all sources)"
        else
            warn "Failed to install $package via apt-get, trying with --allow-unauthenticated..."
            if apt-get install -y -qq --allow-unauthenticated "$package"; then
                log "Successfully installed $package (with --allow-unauthenticated)"
            else
                if [[ "$package" == "net-tools" ]]; then
                    warn "Failed to install net-tools, will use 'ss' command instead of 'netstat'"
                elif [[ "$package" == "ufw" ]]; then
                    warn "Failed to install ufw, firewall configuration will be skipped"
                elif [[ "$package" == "curl" ]]; then
                    warn "Failed to install curl, endpoint testing will be limited"
                else
                    error "Critical package $package could not be installed"
                    cleanup_temp_sources
                    exit 1
                fi
            fi
        fi
    done

    log "Installing Python requests module..."
    
    # Try installing python3-requests with clean sources first
    if run_clean_apt install -y -qq python3-requests; then
        log "Successfully installed python3-requests via apt-get (clean sources)"
    elif apt-get install -y -qq python3-requests; then
        log "Successfully installed python3-requests via apt-get"
    elif apt-get install -y -qq --allow-unauthenticated python3-requests; then
        log "Successfully installed python3-requests via apt-get (with --allow-unauthenticated)"
    else
        warn "Failed to install python3-requests via apt-get, trying pip..."
        # Try different pip installation methods
        if pip3 install requests; then
            log "Successfully installed requests via pip3"
        elif pip3 install --break-system-packages requests; then
            log "Successfully installed requests via pip3 (with --break-system-packages)"
        elif python3 -m pip install requests; then
            log "Successfully installed requests via python3 -m pip"
        elif python3 -m pip install --break-system-packages requests; then
            log "Successfully installed requests via python3 -m pip (with --break-system-packages)"
        else
            error "Failed to install requests module through all methods"
            error "Please install python3-requests manually: apt-get install python3-requests"
            cleanup_temp_sources
            exit 1
        fi
    fi
    
    # Clean up temporary sources
    cleanup_temp_sources
}

# Helper function to clean up temporary sources
cleanup_temp_sources() {
    if [[ -d "/tmp/apt-sources-clean" ]]; then
        rm -rf "/tmp/apt-sources-clean"
    fi
}

create_python_script() {
    log "Downloading and configuring JSON proxy Python script..."

    # Generate cache-busting parameters
    timestamp=$(date +%s)
    random_num=$((RANDOM % 10000))
    cache_bust="${timestamp}_${random_num}"
    
    # Download the Python script template from GitHub
    if wget --no-cache --no-cookies --user-agent="ChillXandController/${timestamp}" -O /tmp/json-proxy-template.py "https://raw.githubusercontent.com/mrhcon/chillxand-controller/main/json-proxy.py?cb=${cache_bust}"; then

        log "Successfully downloaded Python script template"
    else
        error "Failed to download Python script template from GitHub"
        exit 1
    fi

    # Build the Python IP list from our bash array
    python_ip_list=""
    for ip in "${!ALLOWED_IPS[@]}"; do
        if [[ "$ip" == "::1" ]]; then
            python_ip_list+="    '::1',"$'\n'
        else
            python_ip_list+="    '$ip',   # ${ALLOWED_IPS[$ip]}"$'\n'
        fi
    done
    
    # Replace placeholders
    sed -e "s/{{CHILLXAND_VERSION}}/$CHILLXAND_VERSION/g" \
        -e "/{{ALLOWED_IPS}}/r /dev/stdin" \
        -e "/{{ALLOWED_IPS}}/d" \
        /tmp/json-proxy-template.py > /opt/json-proxy.py << EOF
$python_ip_list
EOF

    # Clean up temp file
    rm -f /tmp/json-proxy-template.py
    
    # Make it executable
    chmod +x /opt/json-proxy.py
    log "Python script configured with version $CHILLXAND_VERSION and made executable"
}

# Create systemd service
create_systemd_service() {
    log "Creating systemd service file..."
    
    cat > /etc/systemd/system/json-proxy.service << 'EOF'
[Unit]
Description=JSON Proxy Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt
ExecStart=/usr/bin/python3 /opt/json-proxy.py
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    log "Systemd service file created"
}

# Enable and start the service
setup_service() {
    log "Reloading systemd daemon..."
    systemctl daemon-reload
    
    log "Enabling json-proxy service..."
    systemctl enable json-proxy.service
    
    # Check if service is already running and restart if so, otherwise start fresh
    if systemctl is-active --quiet json-proxy.service; then
        log "Service is already running, restarting to pick up new script..."

        # Create marker file to indicate expected termination
        touch /tmp/update-in-progress
        
        systemctl restart json-proxy.service

        # If we get here, restart completed normally (shouldn't happen during update)
        rm -f /tmp/update-in-progress
    else
        log "Starting json-proxy service..."
        systemctl start json-proxy.service
    fi
    
    # Wait a moment for service to start
    sleep 3
    
    log "Checking service status..."
    if systemctl is-active --quiet json-proxy.service; then
        log "Service is running successfully"
        
        # Get the process start time to confirm it's using the new script
        service_pid=$(systemctl show json-proxy.service -p MainPID --value)
        if [[ -n "$service_pid" && "$service_pid" != "0" ]]; then
            start_time=$(ps -o lstart= -p "$service_pid" 2>/dev/null || echo "unknown")
            log "Service PID: $service_pid, Started: $start_time"
        fi
    else
        warn "Service may not be running properly"
        systemctl status json-proxy.service --no-pager
        warn "Check logs with: journalctl -u json-proxy.service -f"
    fi
}

# Configure firewall with IP restrictions
# setup_firewall() {
#     log "Configuring UFW firewall with IP restrictions..."
    
#     # Check if UFW is installed and available
#     if ! command -v ufw &> /dev/null; then
#         warn "UFW is not installed or not available. Skipping firewall configuration."
#         warn "Port 3001 may not be accessible from outside without manual firewall configuration."
#         return
#     fi
    
#     # Reset UFW rules to ensure clean state
#     log "Resetting UFW rules..."
#     ufw --force reset
    
#     # Set default policies
#     log "Setting default UFW policies..."
#     ufw default deny incoming
#     ufw default allow outgoing
    
#     # Allow SSH (important - don't lock yourself out!)
#     log "Allowing SSH access..."
#     ufw allow ssh
    
#     # Allow the specific IPs to access port 3001
#     log "Adding IP whitelist rules for port 3001..."
    
#     # Master (USA)
#     ufw allow from 74.208.234.116 to any port 3001 comment 'Master USA'
#     log "Added rule for Master (USA): 74.208.234.116"
    
#     # Control2 (Germany)
#     ufw allow from 85.215.145.173 to any port 3001 comment 'Control2 Germany'
#     log "Added rule for Control2 (Germany): 85.215.145.173"
    
#     # Control3 (Spain)
#     ufw allow from 194.164.163.124 to any port 3001 comment 'Control3 Spain'
#     log "Added rule for Control3 (Spain): 194.164.163.124"
    
#     # Home
#     ufw allow from 174.114.192.84 to any port 3001 comment 'Home'
#     log "Added rule for Home: 174.114.192.84"

#     # Home #2
#     ufw allow from 67.70.165.78 to any port 3001 comment 'Home'
#     log "Added rule for Home #2: 67.70.165.78"
    
#     # Allow localhost access
#     ufw allow from 127.0.0.1 to any port 3001 comment 'Localhost'
#     log "Added rule for localhost: 127.0.0.1"
    
#     # Explicitly deny all other access to port 3001
#     ufw deny 3001 comment 'Deny all other access to port 3001'
#     log "Added deny rule for all other IPs on port 3001"
    
#     # Enable UFW
#     log "Enabling UFW firewall..."
#     ufw --force enable
    
#     # Show the status
#     log "UFW firewall configuration complete. Current rules:"
#     ufw status numbered
# }
setup_firewall() {
    log "Configuring UFW firewall with IP restrictions..."
    
    # Check if UFW is installed and available
    if ! command -v ufw &> /dev/null; then
        warn "UFW is not installed or not available. Skipping firewall configuration."
        warn "Port 3001 may not be accessible from outside without manual firewall configuration."
        return
    fi
    
    # Check if UFW is enabled
    ufw_status=$(ufw status | head -1)
    if [[ "$ufw_status" == *"inactive"* ]]; then
        log "UFW is inactive, will configure and enable..."
        needs_setup=true
    else
        log "UFW is active, checking existing rules..."
        needs_setup=false
        
        # Check if all required rules exist
        for ip in "${!ALLOWED_IPS[@]}"; do
            if [[ "$ip" != "127.0.0.1" ]] && ! ufw status | grep -q "3001.*$ip"; then
                log "Missing rule for $ip (${ALLOWED_IPS[$ip]})"
                needs_setup=true
                break
            fi
        done
        
        # Check if deny rule exists for port 3001
        if ! ufw status | grep -q "3001.*DENY"; then
            log "Missing deny rule for port 3001"
            needs_setup=true
        fi
        
        # Check if SSH is allowed
        if ! ufw status | grep -q -E "(22|ssh).*ALLOW"; then
            log "Missing SSH rule"
            needs_setup=true
        fi
    fi
    
    if [[ "$needs_setup" == "false" ]]; then
        log "All required UFW rules already exist, skipping firewall configuration"
        return
    fi
    
    log "UFW configuration needed, proceeding with setup..."
    
    # Only reset if we really need to reconfigure
    log "Resetting UFW rules..."
    ufw --force reset
    
    # Set default policies
    log "Setting default UFW policies..."
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (important - don't lock yourself out!)
    log "Allowing SSH access..."
    ufw allow ssh
    
    # Allow the specific IPs to access port 3001
    log "Adding IP whitelist rules for port 3001..."
    
    for ip in "${!ALLOWED_IPS[@]}"; do
        # Skip localhost for UFW rules (it's allowed by default)
        if [[ "$ip" != "127.0.0.1" ]]; then
            ufw allow from "$ip" to any port 3001 comment "${ALLOWED_IPS[$ip]}"
            log "Added rule for $ip (${ALLOWED_IPS[$ip]})"
        fi
    done
    
    # Explicitly deny all other access to port 3001
    ufw deny 3001 comment 'Deny all other access to port 3001'
    log "Added deny rule for all other IPs on port 3001"
    
    # Enable UFW
    log "Enabling UFW firewall..."
    ufw --force enable
    
    # Show the status
    log "UFW firewall configuration complete. Current rules:"
    ufw status numbered
}

# Test the installation
test_installation() {
    log "Testing installation..."
    
    # Test if the service is listening on port 3001
    port_check_success=false
    
    if command -v netstat &> /dev/null; then
        if netstat -tlnp 2>/dev/null | grep -q ":3001 "; then
            log "Service is listening on port 3001 (detected via netstat)"
            port_check_success=true
        fi
    fi
    
    if ! $port_check_success && command -v ss &> /dev/null; then
        if ss -tlnp 2>/dev/null | grep -q ":3001 "; then
            log "Service is listening on port 3001 (detected via ss)"
            port_check_success=true
        fi
    fi
    
    if ! $port_check_success; then
        warn "Could not verify if service is listening on port 3001"
        warn "This could be due to missing network tools or service startup delay"
    fi
    
    # Test endpoints
    if command -v curl &> /dev/null; then
        log "Testing endpoints..."
        sleep 3  # Give service time to fully start
        
        # Test health endpoint
        for attempt in 1 2 3; do
            if curl -s -f -m 10 "http://localhost:3001/health" > /dev/null 2>&1; then
                log "✓ /health endpoint responding successfully"
                break
            else
                warn "Attempt $attempt: /health endpoint not responding, waiting..."
                sleep 2
            fi
        done
        
        # Test summary endpoint
        for attempt in 1 2 3; do
            if curl -s -f -m 10 "http://localhost:3001/summary" > /dev/null 2>&1; then
                log "✓ /summary endpoint responding successfully"
                break
            else
                warn "Attempt $attempt: /summary endpoint not responding, waiting..."
                sleep 2
            fi
        done
        
        # Test stats endpoint
        if curl -s -f -m 10 "http://localhost:3001/stats" > /dev/null 2>&1; then
            log "✓ /stats endpoint responding successfully"
        else
            info "✗ /stats endpoint not responding (may be normal if upstream service is down)"
        fi
        
        # Test versions endpoint
        if curl -s -f -m 10 "http://localhost:3001/versions" > /dev/null 2>&1; then
            log "✓ /versions endpoint responding successfully"
        else
            info "✗ /versions endpoint not responding (may be normal if upstream service is down)"
        fi
        
        # Test status endpoints for each service
        log "Testing service status endpoints..."
        
        if curl -s -m 5 "http://localhost:3001/status/pod" > /dev/null 2>&1; then
            log "✓ /status/pod endpoint responding successfully"
        else
            warn "✗ /status/pod endpoint not responding"
        fi
        
        if curl -s -m 5 "http://localhost:3001/status/xandminer" > /dev/null 2>&1; then
            log "✓ /status/xandminer endpoint responding successfully"
        else
            warn "✗ /status/xandminer endpoint not responding"
        fi
        
        if curl -s -m 5 "http://localhost:3001/status/xandminerd" > /dev/null 2>&1; then
            log "✓ /status/xandminerd endpoint responding successfully"
        else
            warn "✗ /status/xandminerd endpoint not responding"
        fi
        
    else
        info "curl not available for testing HTTP endpoints"
        info "You can test manually with: curl http://localhost:3001/health"
    fi
}

# Display final information
show_completion_info() {
    echo
    log "============================================="
    log "JSON Proxy Service Installation Complete!"
    log "============================================="
    echo
    info "Service Details:"
    echo "  - Service Name: json-proxy.service"
    echo "  - Port: 3001"
    echo "  - Script Location: /opt/json-proxy.py"
    echo "  - Service File: /etc/systemd/system/json-proxy.service"
    echo
    info "Available Endpoints:"
    echo "  - GET /health       - RFC-compliant health check with service monitoring"
    echo "  - GET /summary      - Complete system summary with controller version"
    echo "  - GET /stats        - Proxy to localhost:80/stats"
    echo "  - GET /versions     - Proxy to localhost:4000/versions + controller version"
    echo "  - GET /status/pod   - Pod service status"
    echo "  - GET /status/xandminer - Xandminer service status"
    echo "  - GET /status/xandminerd - Xandminerd service status"
    echo "  - GET /restart/pod  - Restart pod service (creates symlink)"
    echo "  - GET /restart/xandminer - Restart xandminer service"
    echo "  - GET /restart/xandminerd - Restart xandminerd service"
    echo "  - GET /update/controller - Update controller script from GitHub"
    echo "  - GET /update/controller/log - View update log from last update operation"
    echo
    info "Version Information:"
    echo "  - ChillXand Controller Version: ${CHILLXAND_VERSION}"
    echo "  - Version shown in /health, /summary, and /versions endpoints"
    echo "  - Controller version included alongside upstream versions"
    echo
    info "Security Features:"
    echo "  - IP Whitelisting: ENABLED"
    echo "  - Allowed IPs:"
    echo "    * 74.208.234.116 (Master - USA)"
    echo "    * 85.215.145.173 (Control2 - Germany)"
    echo "    * 194.164.163.124 (Control3 - Spain)"
    echo "    * 174.114.192.84 (Home)"
    echo "    * 67.70.165.78 (Home #2)"    
    echo "    * 127.0.0.1 (Localhost)"
    echo "  - All other IPs will receive 403 Forbidden"
    echo "  - UFW Firewall: Configured with IP restrictions"
    echo "  - Request logging: Enabled with IP tracking"
    echo
    info "Health Check Features:"
    echo "  - Enhanced CPU monitoring (load + usage percentage)"
    echo "  - Enhanced memory monitoring (RAM + swap details)"
    echo "  - Network statistics (packets/bytes transferred)"
    echo "  - Service status monitoring (pod, xandminer, xandminerd)"
    echo "  - Application endpoint checks (stats, versions)"
    echo "  - RFC-compliant response format"
    echo "  - Proxy version tracking"
    echo "  - Disk space monitoring: DISABLED (commented out)"
    echo
    info "Useful Commands:"
    echo "  - Check service status: systemctl status json-proxy.service"
    echo "  - View service logs: journalctl -u json-proxy.service -f"
    echo "  - Restart service: systemctl restart json-proxy.service"
    echo "  - Stop service: systemctl stop json-proxy.service"
    echo "  - Test health endpoint: curl http://localhost:3001/health"
    echo "  - Test summary endpoint: curl http://localhost:3001/summary"
    echo "  - Test versions endpoint: curl http://localhost:3001/versions"
    echo "  - Update controller: curl http://localhost:3001/update/controller"
    echo "  - Check update log: curl http://localhost:3001/update/controller/log"
    echo
    info "Example Health Check Usage:"
    echo "  curl -s http://localhost:3001/health | jq '.status'"
    echo "  curl -s http://localhost:3001/health | jq '.chillxand_controller_version'"
    echo "  curl -s http://localhost:3001/versions | jq '.data.chillxand_controller'"
    echo
    log "Installation completed successfully!"
}

# Cleanup function for script interruption
# cleanup() {
#     error "Script interrupted. Cleaning up..."
#     exit 1
# }
cleanup() {
    # Check if this is expected termination during service restart
    if [[ -f "/tmp/update-in-progress" ]]; then
        info "Update process terminating as expected during service restart"
        info "Service will restart with new version and run validation"
        rm -f /tmp/update-in-progress
        exit 0
    else
        error "Script interrupted. Cleaning up..."
        exit 1
    fi
}

# Main installation function
main() {
    trap cleanup INT TERM
    
    log "Starting JSON Proxy Service Installation..."
    
    check_root
    install_dependencies
    create_python_script
    create_systemd_service
    setup_service
    setup_
    test_installation
    show_completion_info
}

# Run the main function
main "$@"
