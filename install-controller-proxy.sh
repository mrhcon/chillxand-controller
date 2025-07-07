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
    for package in ufw python3 python3-pip net-tools; do
        if ! apt install -y "$package"; then
            warn "Failed to install $package via apt, trying with --allow-unauthenticated..."
            if ! apt install -y --allow-unauthenticated "$package"; then
                if [[ "$package" == "net-tools" ]]; then
                    warn "Failed to install net-tools, will use 'ss' command instead of 'netstat'"
                elif [[ "$package" == "ufw" ]]; then
                    warn "Failed to install ufw, firewall configuration will be skipped"
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
import os
import shutil
from datetime import datetime

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
    
    def _get_current_time(self):
        """Get current time in ISO format"""
        return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    
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
    
    def _get_health_data(self):
        """
        Standard health check response format based on RFC draft
        https://datatracker.ietf.org/doc/html/draft-inadarei-api-health-check
        """
        health_data = {
            "status": "pass",  # pass, fail, warn
            "version": "1",
            "serviceId": "xandeum-node",
            "description": "Xandeum Node Health Check",
            "checks": {},
            "links": {},
            "notes": []
        }
        
        overall_status = "pass"
        current_time = self._get_current_time()
        
        try:
            # Check system load
            with open('/proc/loadavg', 'r') as f:
                load_avg = f.read().strip().split()
                load_1min = float(load_avg[0])
                
            # Get CPU count for load assessment
            cpu_count = os.cpu_count() or 1
            load_per_cpu = load_1min / cpu_count
            
            if load_per_cpu > 2.0:
                load_status = "fail"
                overall_status = "fail"
            elif load_per_cpu > 1.0:
                load_status = "warn"
                if overall_status == "pass":
                    overall_status = "warn"
            else:
                load_status = "pass"
                
            health_data["checks"]["system:load"] = {
                "status": load_status,
                "observedValue": load_1min,
                "observedUnit": "load_average",
                "time": current_time
            }
            
        except Exception as e:
            health_data["checks"]["system:load"] = {
                "status": "fail",
                "output": str(e)
            }
            overall_status = "fail"
        
        try:
            # Check disk space
            disk_usage = shutil.disk_usage('/')
            free_percent = (disk_usage.free / disk_usage.total) * 100
            
            if free_percent < 5:
                disk_status = "fail"
                overall_status = "fail"
            elif free_percent < 15:
                disk_status = "warn"
                if overall_status == "pass":
                    overall_status = "warn"
            else:
                disk_status = "pass"
                
            health_data["checks"]["system:disk"] = {
                "status": disk_status,
                "observedValue": round(free_percent, 1),
                "observedUnit": "percent_free",
                "time": current_time
            }
            
        except Exception as e:
            health_data["checks"]["system:disk"] = {
                "status": "fail",
                "output": str(e)
            }
            overall_status = "fail"
        
        try:
            # Check memory
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
                
            mem_total = None
            mem_available = None
            for line in meminfo.split('\n'):
                if line.startswith('MemTotal:'):
                    mem_total = int(line.split()[1]) * 1024  # Convert KB to bytes
                elif line.startswith('MemAvailable:'):
                    mem_available = int(line.split()[1]) * 1024  # Convert KB to bytes
                    
            if mem_total and mem_available:
                mem_used_percent = ((mem_total - mem_available) / mem_total) * 100
                
                if mem_used_percent > 95:
                    mem_status = "fail"
                    overall_status = "fail"
                elif mem_used_percent > 85:
                    mem_status = "warn"
                    if overall_status == "pass":
                        overall_status = "warn"
                else:
                    mem_status = "pass"
                    
                health_data["checks"]["system:memory"] = {
                    "status": mem_status,
                    "observedValue": round(mem_used_percent, 1),
                    "observedUnit": "percent_used",
                    "time": current_time
                }
            
        except Exception as e:
            health_data["checks"]["system:memory"] = {
                "status": "fail",
                "output": str(e)
            }
            overall_status = "fail"
        
        # Check services
        services = ['pod.service', 'xandminer.service', 'xandminerd.service']
        for service in services:
            try:
                is_active = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True,
                    text=True,
                    timeout=5
                ).stdout.strip()
                
                service_name = service.replace('.service', '')
                if is_active == 'active':
                    service_status = "pass"
                elif is_active == 'inactive':
                    service_status = "warn"
                    if overall_status == "pass":
                        overall_status = "warn"
                else:
                    service_status = "fail"
                    overall_status = "fail"
                    
                health_data["checks"][f"service:{service_name}"] = {
                    "status": service_status,
                    "observedValue": is_active,
                    "time": current_time
                }
                
            except Exception as e:
                health_data["checks"][f"service:{service_name}"] = {
                    "status": "fail",
                    "output": str(e)
                }
                overall_status = "fail"
        
        # Check application endpoints
        try:
            response = requests.get('http://localhost:80/stats', timeout=5)
            if response.status_code == 200:
                app_status = "pass"
            else:
                app_status = "fail"
                overall_status = "fail"
                
            health_data["checks"]["app:stats"] = {
                "status": app_status,
                "observedValue": response.status_code,
                "time": current_time
            }
            
        except Exception as e:
            health_data["checks"]["app:stats"] = {
                "status": "fail",
                "output": str(e)
            }
            overall_status = "fail"
        
        try:
            response = requests.get('http://localhost:4000/versions', timeout=5)
            if response.status_code == 200:
                versions_status = "pass"
            else:
                versions_status = "fail"
                overall_status = "fail"
                
            health_data["checks"]["app:versions"] = {
                "status": versions_status,
                "observedValue": response.status_code,
                "time": current_time
            }
            
        except Exception as e:
            health_data["checks"]["app:versions"] = {
                "status": "fail",
                "output": str(e)
            }
            overall_status = "fail"
        
        health_data["status"] = overall_status
        
        # Add links
        health_data["links"] = {
            "stats": "http://localhost:3001/stats",
            "versions": "http://localhost:3001/versions",
            "summary": "http://localhost:3001/summary"
        }
        
        return health_data
    
    def _get_stats_data(self):
        try:
            response = requests.get('http://localhost:80/stats', timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'HTTP {response.status_code}', 'message': 'Failed to fetch stats'}
        except requests.exceptions.RequestException as e:
            return {'error': 'Connection failed', 'message': str(e)}
        except Exception as e:
            return {'error': 'Unexpected error', 'message': str(e)}
    
    def _get_versions_data(self):
        try:
            response = requests.get('http://localhost:4000/versions', timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'HTTP {response.status_code}', 'message': 'Failed to fetch versions'}
        except requests.exceptions.RequestException as e:
            return {'error': 'Connection failed', 'message': str(e)}
        except Exception as e:
            return {'error': 'Unexpected error', 'message': str(e)}
    
    def _get_summary_data(self):
        summary = {
            'timestamp': self._get_current_time(),
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
                'restart_error': restart_result.stderr if restart_result.stderr else None,
                'timestamp': self._get_current_time()
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
                'restart_error': restart_result.stderr if restart_result.stderr else None,
                'timestamp': self._get_current_time()
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
    
    def _send_json_response(self, data, status_code=200):
        """Helper method to send JSON responses"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self._set_cors_headers()
        self.end_headers()
        
        json_response = json.dumps(data, indent=2)
        self.wfile.write(json_response.encode('utf-8'))
    
    def do_GET(self):
        try:
            if self.path == '/stats':
                response = requests.get('http://localhost:80/stats', timeout=10)
                
                self.send_response(response.status_code)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                
                self.wfile.write(response.content)
                
            elif self.path == '/versions':
                response = requests.get('http://localhost:4000/versions', timeout=10)
                
                self.send_response(response.status_code)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                
                self.wfile.write(response.content)
                
            elif self.path == '/health':
                health_data = self._get_health_data()
                
                # Return appropriate HTTP status based on health
                if health_data['status'] == 'pass':
                    http_status = 200
                elif health_data['status'] == 'warn':
                    http_status = 200  # Some prefer 200 for warnings
                else:  # fail
                    http_status = 503  # Service Unavailable
                
                self._send_json_response(health_data, http_status)
                
            elif self.path == '/summary':
                summary_data = self._get_summary_data()
                self._send_json_response(summary_data)
                
            elif self.path == '/status/pod':
                status_data = self._get_service_status('pod.service')
                self._send_json_response(status_data)
                
            elif self.path == '/status/xandminer':
                status_data = self._get_service_status('xandminer.service')
                self._send_json_response(status_data)
                
            elif self.path == '/status/xandminerd':
                status_data = self._get_service_status('xandminerd.service')
                self._send_json_response(status_data)
                
            elif self.path == '/restart/pod':
                status_data = self._restart_pod_service()
                self._send_json_response(status_data)
                
            elif self.path == '/restart/xandminer':
                status_data = self._restart_service('xandminer.service')
                self._send_json_response(status_data)
                
            elif self.path == '/restart/xandminerd':
                status_data = self._restart_service('xandminerd.service')
                self._send_json_response(status_data)
                
            else:
                # Return 404 for any other path
                self.send_error(404, "Not Found")
                
        except Exception as e:
            print(f"Error handling GET request: {e}")
            self.send_error(500, str(e))
    
    def do_POST(self):
        self.send_error(405, "Method Not Allowed")
    
    def do_PUT(self):
        self.send_error(405, "Method Not Allowed")
    
    def do_DELETE(self):
        self.send_error(405, "Method Not Allowed")
    
    def log_message(self, format, *args):
        """Override to reduce verbose logging"""
        return

PORT = 3001
if __name__ == "__main__":
    try:
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
    
    log "Starting json-proxy service..."
    systemctl start json-proxy.service
    
    # Wait a moment for service to start
    sleep 3
    
    log "Checking service status..."
    if systemctl is-active --quiet json-proxy.service; then
        log "Service is running successfully"
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
    
    # Test a simple endpoint
    if command -v curl &> /dev/null; then
        log "Testing /summary endpoint..."
        sleep 3  # Give service time to fully start
        
        # Try multiple times with increasing delays
        for attempt in 1 2 3; do
            if curl -s -f -m 10 "http://localhost:3001/summary" > /dev/null 2>&1; then
                log "Service responds successfully to HTTP requests"
                return 0
            else
                warn "Attempt $attempt: Service not responding, waiting..."
                sleep 2
            fi
        done
        
        warn "Service may not be responding to HTTP requests after 3 attempts"
        warn "Check service status: systemctl status json-proxy.service"
        warn "Check service logs: journalctl -u json-proxy.service -n 20"
    else
        info "curl not available for testing HTTP endpoints"
        info "You can test manually with: curl http://localhost:3001/summary"
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
    echo "  - GET /health       - RFC-compliant health check"
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
