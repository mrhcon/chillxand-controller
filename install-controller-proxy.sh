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
    apt update

    log "Installing required packages..."
    apt install -y ufw python3 python3-pip

    log "Installing Python requests module..."
    # Try to install python3-requests via apt first (preferred method)
    if apt install -y python3-requests; then
        log "Successfully installed python3-requests via apt"
    else
        warn "Failed to install python3-requests via apt, trying pip with --break-system-packages"
        pip3 install --break-system-packages requests
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
import os

class ReadOnlyHandler(http.server.BaseHTTPRequestHandler):
    def _set_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Max-Age', '86400')
    
    def do_OPTIONS(self):
        # Handle preflight requests
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()
    
    def _get_service_status(self, service_name):
        try:
            # Get service status
            result = subprocess.run(
                ['systemctl', 'status', service_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Get additional info
            is_active = subprocess.run(
                ['systemctl', 'is-active', service_name],
                capture_output=True,
                text=True,
                timeout=5
            ).stdout.strip()
            
            is_enabled = subprocess.run(
                ['systemctl', 'is-enabled', service_name],
                capture_output=True,
                text=True,
                timeout=5
            ).stdout.strip()
            
            # Parse status output into messages
            status_messages = []
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():  # Skip empty lines
                        status_messages.append(line)
            
            return {
                'service': service_name,
                'active': is_active,
                'enabled': is_enabled,
                'status_messages': status_messages,
                'return_code': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                'service': service_name,
                'error': 'Command timed out',
                'active': 'unknown',
                'enabled': 'unknown',
                'status_messages': []
            }
        except Exception as e:
            return {
                'service': service_name,
                'error': str(e),
                'active': 'unknown',
                'enabled': 'unknown',
                'status_messages': []
            }
    
    def _get_stats_data(self):
        try:
            response = requests.get('http://localhost:80/stats', timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _get_versions_data(self):
        try:
            response = requests.get('http://localhost:4000/versions', timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}
    
    def _get_summary_data(self):
        summary = {
            'timestamp': subprocess.run(['date', '-u', '+%Y-%m-%dT%H:%M:%SZ'], 
                                      capture_output=True, text=True).stdout.strip(),
            'stats': self._get_stats_data(),
            'versions': self._get_versions_data(),
            'services': {
                'pod': self._get_service_status('pod.service'),
                'xandminer': self._get_service_status('xandminer.service'),
                'xandminerd': self._get_service_status('xandminerd.service')
            }
        }
        return summary
    
    def _restart_pod_service(self):
        try:
            # Create symlink
            symlink_result = subprocess.run(
                ['ln', '-sf', '/xandeum-pages', '/run/xandeum-pod'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Restart service
            restart_result = subprocess.run(
                ['systemctl', 'restart', 'pod.service'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Get status
            status_data = self._get_service_status('pod.service')
            
            # Add restart operation info
            status_data['restart_operation'] = {
                'symlink_created': symlink_result.returncode == 0,
                'restart_success': restart_result.returncode == 0,
                'symlink_error': symlink_result.stderr if symlink_result.stderr else None,
                'restart_error': restart_result.stderr if restart_result.stderr else None
            }
            
            return status_data
            
        except Exception as e:
            return {
                'service': 'pod.service',
                'error': f'Restart operation failed: {str(e)}',
                'active': 'unknown',
                'enabled': 'unknown',
                'status_messages': []
            }
    
    def _restart_service(self, service_name):
        try:
            # Restart service
            restart_result = subprocess.run(
                ['systemctl', 'restart', service_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Get status
            status_data = self._get_service_status(service_name)
            
            # Add restart operation info
            status_data['restart_operation'] = {
                'restart_success': restart_result.returncode == 0,
                'restart_error': restart_result.stderr if restart_result.stderr else None
            }
            
            return status_data
            
        except Exception as e:
            return {
                'service': service_name,
                'error': f'Restart operation failed: {str(e)}',
                'active': 'unknown',
                'enabled': 'unknown',
                'status_messages': []
            }
    
    def do_GET(self):
        if self.path == '/stats':
            try:
                response = requests.get('http://localhost:80/stats')
                
                self.send_response(response.status_code)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                
                self.wfile.write(response.content)
                
            except Exception as e:
                self.send_error(500, str(e))
                
        elif self.path == '/versions':
            try:
                response = requests.get('http://localhost:4000/versions')
                
                self.send_response(response.status_code)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                
                self.wfile.write(response.content)
                
            except Exception as e:
                self.send_error(500, str(e))
                
        elif self.path == '/summary':
            try:
                summary_data = self._get_summary_data()
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                
                json_response = json.dumps(summary_data, indent=2)
                self.wfile.write(json_response.encode('utf-8'))
                
            except Exception as e:
                self.send_error(500, str(e))
                
        elif self.path == '/status/pod':
            try:
                status_data = self._get_service_status('pod.service')
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                
                json_response = json.dumps(status_data, indent=2)
                self.wfile.write(json_response.encode('utf-8'))
                
            except Exception as e:
                self.send_error(500, str(e))
                
        elif self.path == '/status/xandminer':
            try:
                status_data = self._get_service_status('xandminer.service')
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                
                json_response = json.dumps(status_data, indent=2)
                self.wfile.write(json_response.encode('utf-8'))
                
            except Exception as e:
                self.send_error(500, str(e))
                
        elif self.path == '/status/xandminerd':
            try:
                status_data = self._get_service_status('xandminerd.service')
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                
                json_response = json.dumps(status_data, indent=2)
                self.wfile.write(json_response.encode('utf-8'))
                
            except Exception as e:
                self.send_error(500, str(e))
                
        elif self.path == '/restart/pod':
            try:
                status_data = self._restart_pod_service()
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                
                json_response = json.dumps(status_data, indent=2)
                self.wfile.write(json_response.encode('utf-8'))
                
            except Exception as e:
                self.send_error(500, str(e))
                
        elif self.path == '/restart/xandminer':
            try:
                status_data = self._restart_service('xandminer.service')
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                
                json_response = json.dumps(status_data, indent=2)
                self.wfile.write(json_response.encode('utf-8'))
                
            except Exception as e:
                self.send_error(500, str(e))
                
        elif self.path == '/restart/xandminerd':
            try:
                status_data = self._restart_service('xandminerd.service')
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                
                json_response = json.dumps(status_data, indent=2)
                self.wfile.write(json_response.encode('utf-8'))
                
            except Exception as e:
                self.send_error(500, str(e))
        else:
            # Return 404 for any other path
            self.send_error(404, "Not Found")
    
    def do_POST(self):
        self.send_error(405, "Method Not Allowed")
    
    def do_PUT(self):
        self.send_error(405, "Method Not Allowed")
    
    def do_DELETE(self):
        self.send_error(405, "Method Not Allowed")

PORT = 3001
try:
    with socketserver.TCPServer(("", PORT), ReadOnlyHandler) as httpd:
        print(f"JSON proxy serving on port {PORT}")
        httpd.serve_forever()
except KeyboardInterrupt:
    print("Server stopped")
    sys.exit(0)
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
    
    log "Starting json-proxy service..."
    systemctl start json-proxy.service
    
    # Wait a moment for service to start
    sleep 2
    
    log "Checking service status..."
    if systemctl is-active --quiet json-proxy.service; then
        log "Service is running successfully"
    else
        warn "Service may not be running properly"
        systemctl status json-proxy.service
    fi
}

# Configure firewall
setup_firewall() {
    log "Configuring UFW firewall..."
    
    # Check if UFW is active
    if ufw status | grep -q "Status: active"; then
        log "UFW is already active, adding rule for port 3001..."
        ufw allow 3001/tcp
    else
        info "UFW is not active. Adding rule for port 3001..."
        ufw allow 3001/tcp
        warn "UFW is not enabled. You may want to enable it with: sudo ufw enable"
    fi
}

# Test the installation
test_installation() {
    log "Testing installation..."
    
    # Test if the service is listening on port 3001
    if netstat -tlnp 2>/dev/null | grep -q ":3001 "; then
        log "Service is listening on port 3001"
    else
        warn "Service may not be listening on port 3001"
    fi
    
    # Test a simple endpoint
    if command -v curl &> /dev/null; then
        log "Testing /summary endpoint..."
        if curl -s -f "http://localhost:3001/summary" > /dev/null; then
            log "Service responds successfully to HTTP requests"
        else
            warn "Service may not be responding to HTTP requests"
        fi
    else
        info "curl not available for testing HTTP endpoints"
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
    echo "  - GET /summary      - Complete system summary"
    echo "  - GET /stats        - Proxy to localhost:80/stats"
    echo "  - GET /versions     - Proxy to localhost:4000/versions"
    echo "  - GET /status/pod   - Pod service status"
    echo "  - GET /status/xandminer - Xandminer service status"
    echo "  - GET /status/xandminerd - Xandminerd service status"
    echo "  - GET /restart/pod  - Restart pod service"
    echo "  - GET /restart/xandminer - Restart xandminer service"
    echo "  - GET /restart/xandminerd - Restart xandminerd service"
    echo
    info "Useful Commands:"
    echo "  - Check service status: systemctl status json-proxy.service"
    echo "  - View service logs: journalctl -u json-proxy.service -f"
    echo "  - Restart service: systemctl restart json-proxy.service"
    echo "  - Stop service: systemctl stop json-proxy.service"
    echo "  - Test endpoint: curl http://localhost:3001/summary"
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
