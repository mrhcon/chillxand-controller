#!/bin/bash

# ChillXand Controller Installation Script
# Version: Update this for each deployment
CHILLXAND_VERSION="v1.0.22"

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"; }
error() { echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"; }
info() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        exit 1
    fi
}

install_dependencies() {
    log "Installing dependencies..."
    
    if ! apt update; then
        warn "Standard apt update failed, trying alternatives..."
        apt update --allow-unauthenticated || apt update --allow-releaseinfo-change || warn "All apt update methods failed"
    fi

    for package in python3 python3-pip python3-requests curl; do
        if ! apt install -y "$package"; then
            apt install -y --allow-unauthenticated "$package" || warn "Failed to install $package"
        fi
    done
}

create_python_script() {
    log "Creating Python script..."
    
    cat > /opt/json-proxy.py << 'EOF'
#!/usr/bin/env python3
import http.server
import socketserver
import requests
import sys
import subprocess
import json
from datetime import datetime

CHILLXAND_CONTROLLER_VERSION = "VERSION_PLACEHOLDER"

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
    
    def _get_server_ip(self):
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "localhost"
    
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
            return {'service': service_name, 'error': str(e), 'active': 'unknown', 'enabled': 'unknown', 'status_messages': [], 'timestamp': self._get_current_time()}
    
    def _restart_pod_service(self):
        try:
            symlink_result = subprocess.run(['ln', '-sf', '/xandeum-pages', '/run/xandeum-pod'], capture_output=True, text=True, timeout=10)
            restart_result = subprocess.run(['systemctl', 'restart', 'pod.service'], capture_output=True, text=True, timeout=30)
            
            status_data = self._get_service_status('pod.service')
            status_data['restart_operation'] = {
                'symlink_created': symlink_result.returncode == 0,
                'restart_success': restart_result.returncode == 0,
                'timestamp': self._get_current_time()
            }
            return status_data
        except Exception as e:
            return {'service': 'pod.service', 'error': f'Restart failed: {str(e)}', 'timestamp': self._get_current_time()}
    
    def _restart_service(self, service_name):
        try:
            restart_result = subprocess.run(['systemctl', 'restart', service_name], capture_output=True, text=True, timeout=30)
            status_data = self._get_service_status(service_name)
            status_data['restart_operation'] = {
                'restart_success': restart_result.returncode == 0,
                'timestamp': self._get_current_time()
            }
            return status_data
        except Exception as e:
            return {'service': service_name, 'error': f'Restart failed: {str(e)}', 'timestamp': self._get_current_time()}
    
    def _get_health_data(self):
        server_ip = self._get_server_ip()
        health_data = {
            'status': 'pass',
            'chillxand_controller_version': CHILLXAND_CONTROLLER_VERSION,
            'timestamp': self._get_current_time(),
            'links': {
                'stats': f'http://{server_ip}:3001/stats',
                'versions': f'http://{server_ip}:3001/versions',
                'summary': f'http://{server_ip}:3001/summary',
                'status_pod': f'http://{server_ip}:3001/status/pod',
                'status_xandminer': f'http://{server_ip}:3001/status/xandminer',
                'status_xandminerd': f'http://{server_ip}:3001/status/xandminerd',
                'restart_pod': f'http://{server_ip}:3001/restart/pod',
                'restart_xandminer': f'http://{server_ip}:3001/restart/xandminer',
                'restart_xandminerd': f'http://{server_ip}:3001/restart/xandminerd'
            }
        }
        return health_data
    
    def _get_summary_data(self):
        try:
            stats_response = requests.get('http://localhost:80/stats', timeout=5)
            stats_data = stats_response.json() if stats_response.status_code == 200 else {'error': f'HTTP {stats_response.status_code}'}
        except:
            stats_data = {'error': 'Connection failed'}
        
        try:
            versions_response = requests.get('http://localhost:4000/versions', timeout=5)
            if versions_response.status_code == 200:
                versions_data = versions_response.json()
                if isinstance(versions_data, dict) and 'data' in versions_data:
                    versions_data['data']['chillxand_controller'] = CHILLXAND_CONTROLLER_VERSION
                else:
                    versions_data = {'chillxand_controller': CHILLXAND_CONTROLLER_VERSION, 'upstream_data': versions_data}
            else:
                versions_data = {'chillxand_controller': CHILLXAND_CONTROLLER_VERSION, 'error': f'HTTP {versions_response.status_code}'}
        except:
            versions_data = {'chillxand_controller': CHILLXAND_CONTROLLER_VERSION, 'error': 'Connection failed'}
        
        return {
            'timestamp': self._get_current_time(),
            'chillxand_controller_version': CHILLXAND_CONTROLLER_VERSION,
            'stats': stats_data,
            'versions': versions_data,
            'services': {
                'pod': self._get_service_status('pod.service'),
                'xandminer': self._get_service_status('xandminer.service'),
                'xandminerd': self._get_service_status('xandminerd.service')
            }
        }
    
    def _send_json_response(self, data, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self._set_cors_headers()
        self.end_headers()
        json_response = json.dumps(data, indent=2)
        self.wfile.write(json_response.encode('utf-8'))
    
    def do_GET(self):
        try:
            if self.path == '/health':
                self._send_json_response(self._get_health_data())
            elif self.path == '/summary':
                self._send_json_response(self._get_summary_data())
            elif self.path == '/status/pod':
                self._send_json_response(self._get_service_status('pod.service'))
            elif self.path == '/status/xandminer':
                self._send_json_response(self._get_service_status('xandminer.service'))
            elif self.path == '/status/xandminerd':
                self._send_json_response(self._get_service_status('xandminerd.service'))
            elif self.path == '/restart/pod':
                self._send_json_response(self._restart_pod_service())
            elif self.path == '/restart/xandminer':
                self._send_json_response(self._restart_service('xandminer.service'))
            elif self.path == '/restart/xandminerd':
                self._send_json_response(self._restart_service('xandminerd.service'))
            elif self.path == '/stats':
                response = requests.get('http://localhost:80/stats', timeout=10)
                self.send_response(response.status_code)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                self.wfile.write(response.content)
            elif self.path == '/versions':
                try:
                    response = requests.get('http://localhost:4000/versions', timeout=5)
                    if response.status_code == 200:
                        versions_data = response.json()
                        if isinstance(versions_data, dict) and 'data' in versions_data:
                            versions_data['data']['chillxand_controller'] = CHILLXAND_CONTROLLER_VERSION
                        else:
                            versions_data = {'chillxand_controller': CHILLXAND_CONTROLLER_VERSION, 'upstream_data': versions_data}
                        self._send_json_response(versions_data)
                    else:
                        self._send_json_response({'chillxand_controller': CHILLXAND_CONTROLLER_VERSION, 'error': f'HTTP {response.status_code}'})
                except:
                    self._send_json_response({'chillxand_controller': CHILLXAND_CONTROLLER_VERSION, 'error': 'Connection failed'})
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            print(f"Error: {e}")
            self.send_error(500, str(e))
    
    def log_message(self, format, *args):
        return

PORT = 3001
if __name__ == "__main__":
    try:
        print(f"ChillXand Controller {CHILLXAND_CONTROLLER_VERSION} starting on port {PORT}")
        with socketserver.TCPServer(("", PORT), ReadOnlyHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped")
        sys.exit(0)
    except Exception as e:
        print(f"Failed to start server: {e}")
        sys.exit(1)
EOF

    sed -i "s/VERSION_PLACEHOLDER/\"$CHILLXAND_VERSION\"/" /opt/json-proxy.py
    chmod +x /opt/json-proxy.py
}

create_systemd_service() {
    log "Creating systemd service..."
    
    cat > /etc/systemd/system/json-proxy.service << 'EOF'
[Unit]
Description=ChillXand Controller Service
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
}

setup_service() {
    log "Setting up service..."
    
    systemctl daemon-reload
    systemctl enable json-proxy.service
    
    if systemctl is-active --quiet json-proxy.service; then
        log "Restarting existing service..."
        systemctl restart json-proxy.service
    else
        log "Starting new service..."
        systemctl start json-proxy.service
    fi
    
    sleep 3
    
    if systemctl is-active --quiet json-proxy.service; then
        log "Service started successfully"
    else
        warn "Service may not be running properly"
        systemctl status json-proxy.service --no-pager
    fi
}

test_installation() {
    log "Testing installation..."
    
    if command -v curl &> /dev/null; then
        sleep 3
        
        if curl -s -m 5 "http://localhost:3001/health" > /dev/null; then
            log "✓ Health endpoint working"
        else
            warn "✗ Health endpoint not responding"
        fi
        
        if curl -s -m 5 "http://localhost:3001/summary" > /dev/null; then
            log "✓ Summary endpoint working"
        else
            warn "✗ Summary endpoint not responding"
        fi
        
        if curl -s -m 5 "http://localhost:3001/status/pod" > /dev/null; then
            log "✓ Status endpoints working"
        else
            warn "✗ Status endpoints not responding"
        fi
        
        info "Restart endpoints available but not tested during install"
    else
        info "curl not available for testing"
    fi
}

show_completion_info() {
    echo
    log "================================================"
    log "ChillXand Controller Installation Complete!"
    log "================================================"
    echo
    info "Version: ${CHILLXAND_VERSION}"
    info "Port: 3001"
    echo
    info "Available endpoints:"
    echo "  - /health - Health check with links"
    echo "  - /summary - Complete system summary"
    echo "  - /stats - Proxy to localhost:80/stats"
    echo "  - /versions - Proxy to localhost:4000/versions"
    echo "  - /status/[pod|xandminer|xandminerd] - Service status"
    echo "  - /restart/[pod|xandminer|xandminerd] - Restart services"
    echo
    info "Test commands:"
    echo "  curl http://localhost:3001/health"
    echo "  curl http://localhost:3001/summary"
    echo
    log "Installation completed successfully!"
}

main() {
    log "Starting ChillXand Controller installation..."
    
    check_root
    install_dependencies
    create_python_script
    create_systemd_service
    setup_service
    test_installation
    show_completion_info
}

main "$@"
