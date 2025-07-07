#!/bin/bash

# JSON Proxy Service Installation Script
# This script installs and configures the JSON proxy service

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
    log "Updating system packages..."
    # Try multiple approaches for apt update
    if ! apt update; then
        warn "Standard apt update failed, trying with --allow-unauthenticated..."
        if ! apt update --allow-unauthenticated; then
            warn "Apt update with --allow-unauthenticated failed, trying with --allow-releaseinfo-change..."
            if ! apt update --allow-releaseinfo-change; then
                warn "All apt update attempts failed, continuing anyway..."
                warn "Some packages may not be available or up to date"
            fi
        fi
    fi

    log "Installing required packages..."
    # Install packages one by one with fallbacks
    for package in ufw python3 python3-pip net-tools curl; do
        if ! apt install -y "$package"; then
            warn "Failed to install $package via apt, trying with --allow-unauthenticated..."
            if ! apt install -y --allow-unauthenticated "$package"; then
                if [[ "$package" == "net-tools" ]]; then
                    warn "Failed to install net-tools, will use 'ss' command instead of 'netstat'"
                elif [[ "$package" == "ufw" ]]; then
                    warn "Failed to install ufw, firewall configuration will be skipped"
                elif [[ "$package" == "curl" ]]; then
                    warn "Failed to install curl, endpoint testing will be limited"
                else
                    error "Critical package $package could not be installed"
                    exit 1
                fi
            fi
        else
            log "Successfully installed $package"
        fi
    done

    log "Installing Python requests module..."
    # Try to install python3-requests via apt first (preferred method)
    if apt install -y python3-requests; then
        log "Successfully installed python3-requests via apt"
    elif apt install -y --allow-unauthenticated python3-requests; then
        log "Successfully installed python3-requests via apt (with --allow-unauthenticated)"
    else
        warn "Failed to install python3-requests via apt, trying pip..."
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
            error "Please install python3-requests manually: apt install python3-requests"
            exit 1
        fi
    fi
}

# Create the Python script
create_python_script() {
    log "Creating JSON proxy Python script..."
    
    cat > /opt/json-proxy.py << 'EOF'
#!/usr/bin/env python3
import http.server
import socketserver
import requests
import sys
import subprocess
import json
from datetime import datetime

# JSON Proxy Service Version
PROXY_VERSION = "v1.0.0"

class ReadOnlyHandler(http.server.BaseHTTPRequestHandler):
    def _set_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Max-Age', '86400')
    
    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()
    
    def _get_current_time(self):
        return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    
    def _get_service_status(self, service_name):
        try:
            result = subprocess.run(['systemctl', 'status', service_name], capture_output=True, text=True, timeout=10)
            is_active = subprocess.run(['systemctl', 'is-active', service_name], capture_output=True, text=True, timeout=5).stdout.strip()
            is_enabled = subprocess.run(['systemctl', 'is-enabled', service_name], capture_output=True, text=True, timeout=5).stdout.strip()
            
            status_messages = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        status_messages.append(line)
            
            return {
                'service': service_name,
                'active': is_active,
                'enabled': is_enabled,
                'status_messages': status_messages,
                'return_code': result.returncode,
                'timestamp': self._get_current_time()
            }
        except Exception as e:
            return {
                'service': service_name,
                'error': str(e),
                'active': 'unknown',
                'enabled': 'unknown',
                'status_messages': [],
                'timestamp': self._get_current_time()
            }
    
    def _get_stats_data(self):
        try:
            response = requests.get('http://localhost:80/stats', timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _get_versions_data(self):
        try:
            response = requests.get('http://localhost:4000/versions', timeout=5)
            if response.status_code == 200:
                upstream_versions = response.json()
                
                # Add our proxy version to the versions response
                if isinstance(upstream_versions, dict):
                    # If there's a nested data structure, add to it
                    if 'data' in upstream_versions and isinstance(upstream_versions['data'], dict):
                        upstream_versions['data']['json_proxy'] = PROXY_VERSION
                    else:
                        # Add directly to the main object
                        upstream_versions['json_proxy'] = PROXY_VERSION
                else:
                    # If upstream returned something unexpected, create our own structure
                    upstream_versions = {
                        'json_proxy': PROXY_VERSION,
                        'upstream_data': upstream_versions
                    }
            else:
                upstream_versions = {
                    'json_proxy': PROXY_VERSION,
                    'upstream_error': f'HTTP {response.status_code}'
                }
        except Exception as e:
            upstream_versions = {
                'json_proxy': PROXY_VERSION,
                'upstream_error': str(e)
            }
        
        return upstream_versions
    
    def _get_summary_data(self):
        summary = {
            'timestamp': self._get_current_time(),
            'proxy_version': PROXY_VERSION,
            'stats': self._get_stats_data(),
            'versions': self._get_versions_data(),
            'services': {
                'pod': self._get_service_status('pod.service'),
                'xandminer': self._get_service_status('xandminer.service'),
                'xandminerd': self._get_service_status('xandminerd.service')
            }
        }
        return summary
    
    def _get_health_data(self):
        health_data = {
            'status': 'pass',
            'version': '1',
            'serviceId': 'xandeum-node',
            'description': 'Xandeum Node Health Check',
            'proxy_version': PROXY_VERSION,
            'timestamp': self._get_current_time(),
            'checks': {},
            'links': {
                'stats': 'http://localhost:3001/stats',
                'versions': 'http://localhost:3001/versions',
                'summary': 'http://localhost:3001/summary',
                'status_pod': 'http://localhost:3001/status/pod',
                'status_xandminer': 'http://localhost:3001/status/xandminer',
                'status_xandminerd': 'http://localhost:3001/status/xandminerd'
            }
        }
        
        # Check services for health status
        overall_status = 'pass'
        services = ['pod.service', 'xandminer.service', 'xandminerd.service']
        for service in services:
            try:
                is_active = subprocess.run(['systemctl', 'is-active', service], 
                                         capture_output=True, text=True, timeout=5).stdout.strip()
                
                service_name = service.replace('.service', '')
                if is_active == 'active':
                    service_status = 'pass'
                elif is_active == 'inactive':
                    service_status = 'warn'
                    if overall_status == 'pass':
                        overall_status = 'warn'
                else:
                    service_status = 'fail'
                    overall_status = 'fail'
                    
                health_data['checks'][f'service:{service_name}'] = {
                    'status': service_status,
                    'observedValue': is_active,
                    'time': self._get_current_time()
                }
                
            except Exception as e:
                health_data['checks'][f'service:{service_name}'] = {
                    'status': 'fail',
                    'output': str(e)
                }
                overall_status = 'fail'
        
        health_data['status'] = overall_status
        return health_data
    
    def _send_json_response(self, data, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self._set_cors_headers()
        self.end_headers()
        json_response = json.dumps(data, indent=2)
        self.wfile.write(json_response.encode('utf-8'))
    
    def do_GET(self):
        try:
            if self.path == '/status/pod':
                status_data = self._get_service_status('pod.service')
                self._send_json_response(status_data)
                
            elif self.path == '/status/xandminer':
                status_data = self._get_service_status('xandminer.service')
                self._send_json_response(status_data)
                
            elif self.path == '/status/xandminerd':
                status_data = self._get_service_status('xandminerd.service')
                self._send_json_response(status_data)
                
            elif self.path == '/health':
                health_data = self._get_health_data()
                if health_data['status'] == 'pass':
                    http_status = 200
                elif health_data['status'] == 'warn':
                    http_status = 200
                else:
                    http_status = 503
                self._send_json_response(health_data, http_status)
                
            elif self.path == '/summary':
                summary_data = self._get_summary_data()
                self._send_json_response(summary_data)
                
            elif self.path == '/stats':
                response = requests.get('http://localhost:80/stats', timeout=10)
                self.send_response(response.status_code)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(response.content)
                
            elif self.path == '/versions':
                versions_data = self._get_versions_data()
                self._send_json_response(versions_data)
                
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            print(f"Error in do_GET for {self.path}: {e}")
            self.send_error(500, str(e))
    
    def log_message(self, format, *args):
        return

PORT = 3001
if __name__ == "__main__":
    try:
        print(f"JSON Proxy Service {PROXY_VERSION} starting on port {PORT}")
        with socketserver.TCPServer(("", PORT), ReadOnlyHandler) as httpd:
            print(f"JSON proxy serving on port {PORT}")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped")
        sys.exit(0)
    except Exception as e:
        print(f"Failed to start server: {e}")
        sys.exit(1)
EOF

    chmod +x /opt/json-proxy.py
    log "Python script created and made executable"
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
        systemctl restart json-proxy.service
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

# Configure firewall
setup_firewall() {
    log "Configuring UFW firewall..."
    
    # Check if UFW is installed and available
    if ! command -v ufw &> /dev/null; then
        warn "UFW is not installed or not available. Skipping firewall configuration."
        warn "Port 3001 may not be accessible from outside without manual firewall configuration."
        return
    fi
    
    # Check if UFW is active
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        log "UFW is already active, adding rule for port 3001..."
        if ufw allow 3001/tcp; then
            log "Successfully added UFW rule for port 3001"
        else
            warn "Failed to add UFW rule for port 3001"
        fi
    else
        info "UFW is not active. Adding rule for port 3001..."
        if ufw allow 3001/tcp; then
            log "Successfully added UFW rule for port 3001"
            warn "UFW is not enabled. You may want to enable it with: sudo ufw enable"
        else
            warn "Failed to add UFW rule for port 3001"
        fi
    fi
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
    echo "  - GET /summary      - Complete system summary with proxy version"
    echo "  - GET /stats        - Proxy to localhost:80/stats"
    echo "  - GET /versions     - Proxy to localhost:4000/versions + proxy version"
    echo "  - GET /status/pod   - Pod service status"
    echo "  - GET /status/xandminer - Xandminer service status"
    echo "  - GET /status/xandminerd - Xandminerd service status"
    echo
    info "Version Information:"
    echo "  - JSON Proxy Version: v1.0.0"
    echo "  - Version shown in /health, /summary, and /versions endpoints"
    echo "  - Proxy version included alongside upstream versions"
    echo
    info "Health Check Features:"
    echo "  - Service status monitoring (pod, xandminer, xandminerd)"
    echo "  - RFC-compliant response format"
    echo "  - Proxy version tracking"
    echo
    info "Useful Commands:"
    echo "  - Check service status: systemctl status json-proxy.service"
    echo "  - View service logs: journalctl -u json-proxy.service -f"
    echo "  - Restart service: systemctl restart json-proxy.service"
    echo "  - Stop service: systemctl stop json-proxy.service"
    echo "  - Test health endpoint: curl http://localhost:3001/health"
    echo "  - Test summary endpoint: curl http://localhost:3001/summary"
    echo "  - Test versions endpoint: curl http://localhost:3001/versions"
    echo
    info "Example Health Check Usage:"
    echo "  curl -s http://localhost:3001/health | jq '.status'"
    echo "  curl -s http://localhost:3001/health | jq '.proxy_version'"
    echo "  curl -s http://localhost:3001/versions | jq '.data.json_proxy'"
    echo
    log "Installation completed successfully!"
}

# Cleanup function for script interruption
cleanup() {
    error "Script interrupted. Cleaning up..."
    exit 1
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
    setup_firewall
    test_installation
    show_completion_info
}

# Run the main function
main "$@"
