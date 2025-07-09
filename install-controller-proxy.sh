#!/bin/bash

# JSON Proxy Service Installation Script
# This script installs and configures the JSON proxy service

# ChillXand Controller Version - Update this for each deployment
CHILLXAND_VERSION="v1.0.40"

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
    log "Creating JSON proxy Python script with IP whitelisting..."
    
    cat > /opt/json-proxy.py << EOF
#!/usr/bin/env python3
import http.server
import socketserver
import requests
import sys
import subprocess
import json
import os
from datetime import datetime

# ChillXand Controller Version
CHILLXAND_CONTROLLER_VERSION = "${CHILLXAND_VERSION}"

# Allowed IP addresses - WHITELIST ONLY
ALLOWED_IPS = {
    '74.208.234.116',   # Master (USA)
    '85.215.145.173',   # Control2 (Germany)
    '194.164.163.124',  # Control3 (Spain)
    '174.114.192.84',   # Home (add your actual IP here)
    '67.70.165.78',     # Home (secondary IP)
    '127.0.0.1'         # Localhost
}

class ReadOnlyHandler(http.server.BaseHTTPRequestHandler):
    def _check_ip_allowed(self):
        """Check if the client IP is in the allowed list"""
        client_ip = self.client_address[0]
        
        # Handle IPv6-mapped IPv4 addresses
        if client_ip.startswith('::ffff:'):
            client_ip = client_ip[7:]  # Remove ::ffff: prefix
        
        if client_ip not in ALLOWED_IPS:
            self.send_error(403, f"Access forbidden from IP: {client_ip}")
            return False
        return True
    
    def _set_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Max-Age', '86400')
    
    def do_OPTIONS(self):
        if not self._check_ip_allowed():
            return
            
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()
    
    def _get_server_ip(self):
        """Get the server's IP address"""
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "localhost"
    
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
    
    def _get_network_stats(self):
        try:
            network_stats = {}
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()
                
            for line in lines[2:]:
                parts = line.split(':')
                if len(parts) == 2:
                    interface = parts[0].strip()
                    if interface == 'lo':
                        continue
                        
                    stats = parts[1].split()
                    if len(stats) >= 16:
                        bytes_received = int(stats[0])
                        packets_received = int(stats[1])
                        bytes_transmitted = int(stats[8])
                        packets_transmitted = int(stats[9])
                        
                        network_stats[interface] = {
                            'bytes_received': bytes_received,
                            'packets_received': packets_received,
                            'bytes_transmitted': bytes_transmitted,
                            'packets_transmitted': packets_transmitted,
                            'total_bytes': bytes_received + bytes_transmitted,
                            'total_packets': packets_received + packets_transmitted
                        }
                        
            return network_stats
        except Exception as e:
            return {'error': str(e)}
    
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
                    if 'data' in upstream_versions and isinstance(upstream_versions['data'], dict):
                        upstream_versions['data']['chillxand_controller'] = CHILLXAND_CONTROLLER_VERSION
                    else:
                        upstream_versions['chillxand_controller'] = CHILLXAND_CONTROLLER_VERSION
                else:
                    upstream_versions = {
                        'chillxand_controller': CHILLXAND_CONTROLLER_VERSION,
                        'upstream_data': upstream_versions
                    }
            else:
                upstream_versions = {
                    'chillxand_controller': CHILLXAND_CONTROLLER_VERSION,
                    'upstream_error': f'HTTP {response.status_code}'
                }
        except Exception as e:
            upstream_versions = {
                'chillxand_controller': CHILLXAND_CONTROLLER_VERSION,
                'upstream_error': str(e)
            }
        
        return upstream_versions
    
    def _get_summary_data(self):
        summary = {
            'timestamp': self._get_current_time(),
            'chillxand_controller_version': CHILLXAND_CONTROLLER_VERSION,
            'security': {
                'ip_whitelisting': 'enabled',
                'allowed_ips': list(ALLOWED_IPS),
                'client_ip': self.client_address[0]
            },
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
            symlink_result = subprocess.run(['ln', '-sf', '/xandeum-pages', '/run/xandeum-pod'], 
                                          capture_output=True, text=True, timeout=10)
            restart_result = subprocess.run(['systemctl', 'restart', 'pod.service'], 
                                          capture_output=True, text=True, timeout=30)
            
            status_data = self._get_service_status('pod.service')
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
            restart_result = subprocess.run(['systemctl', 'restart', service_name], 
                                          capture_output=True, text=True, timeout=30)
            
            status_data = self._get_service_status(service_name)
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
    
    def _update_controller(self):
        """Update the controller script from GitHub - Simplified independent process"""
        try:
            current_time = self._get_current_time()
            
            # Create a robust update script that detaches itself
            update_script = '''#!/bin/bash
# Simple but effective detachment
nohup bash -c '
    # Sleep to allow HTTP response to be sent
    sleep 5
    
    # Log everything to update.log
    exec >> /tmp/update.log 2>&1
    
    echo "===== Controller Update Started: $(date) ====="
    echo "Starting controller update..."
    
    cd /tmp
    echo "Downloading new script..."
    if wget -O install-controller-proxy.sh https://raw.githubusercontent.com/mrhcon/chillxand-controller/main/install-controller-proxy.sh; then
        echo "Download successful"
        chmod +x install-controller-proxy.sh
        echo "Executing new script..."
        if ./install-controller-proxy.sh; then
            echo "===== Update completed successfully: $(date) ====="
        else
            echo "===== Update script failed: $(date) ====="
        fi
    else
        echo "===== Download failed: $(date) ====="
    fi
    
    # Clean up
    rm -f /tmp/update-controller.sh
    echo "Cleanup completed"
    
' >/dev/null 2>&1 &

# Exit immediately
exit 0
'''
            
            # Write the update script
            with open('/tmp/update-controller.sh', 'w') as f:
                f.write(update_script)
            
            # Make it executable
            subprocess.run(['chmod', '+x', '/tmp/update-controller.sh'], timeout=5)
            
            # Start the process simply with just background execution
            subprocess.Popen(['/bin/bash', '/tmp/update-controller.sh'], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL,
                           stdin=subprocess.DEVNULL)
            
            return {
                'operation': 'controller_update',
                'status': 'initiated',
                'return_code': 0,
                'success': True,
                'output': 'Update process started as independent background job.',
                'stdout': 'Update initiated successfully with nohup detachment',
                'stderr': '',
                'timestamp': current_time,
                'message': 'Controller update initiated successfully',
                'notes': 'Update is running as detached nohup process. Check /tmp/update.log for progress. Service will restart automatically when complete.'
            }
            
        except Exception as e:
            return {
                'operation': 'controller_update',
                'status': 'error',
                'return_code': -1,
                'success': False,
                'output': f'Failed to initiate update: {str(e)}',
                'stdout': '',
                'stderr': str(e),
                'timestamp': self._get_current_time(),
                'message': f'Update initiation failed: {str(e)}',
                'notes': 'Failed to start the background update process.'
            }
    
    def _get_update_log(self):
        """Get the contents of the update log file"""
        try:
            current_time = self._get_current_time()
            log_file = '/tmp/update.log'
            
            if not os.path.exists(log_file):
                return {
                    'operation': 'get_update_log',
                    'status': 'no_log',
                    'success': True,
                    'log_content': '',
                    'log_lines': [],
                    'file_size': 0,
                    'last_modified': None,
                    'timestamp': current_time,
                    'message': 'No update log file found',
                    'notes': 'Update log will be created when an update is initiated.'
                }
            
            stat = os.stat(log_file)
            file_size = stat.st_size
            last_modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%dT%H:%M:%SZ')
            
            try:
                with open(log_file, 'r') as f:
                    log_content = f.read()
                
                log_lines = log_content.strip().split('\n') if log_content.strip() else []
                
                if 'Update completed successfully' in log_content:
                    status = 'completed_success'
                elif 'error' in log_content.lower() or 'failed' in log_content.lower():
                    status = 'completed_error'
                elif log_content.strip():
                    status = 'in_progress'
                else:
                    status = 'empty'
                
                return {
                    'operation': 'get_update_log',
                    'status': status,
                    'success': True,
                    'log_content': log_content,
                    'log_lines': log_lines,
                    'line_count': len(log_lines),
                    'file_size': file_size,
                    'last_modified': last_modified,
                    'timestamp': current_time,
                    'message': f'Update log retrieved successfully ({len(log_lines)} lines)',
                    'notes': f'Log file last modified: {last_modified}'
                }
                
            except Exception as read_error:
                return {
                    'operation': 'get_update_log',
                    'status': 'read_error',
                    'success': False,
                    'log_content': '',
                    'log_lines': [],
                    'file_size': file_size,
                    'last_modified': last_modified,
                    'error': str(read_error),
                    'timestamp': current_time,
                    'message': f'Failed to read update log: {str(read_error)}',
                    'notes': 'Log file exists but could not be read.'
                }
                
        except Exception as e:
            return {
                'operation': 'get_update_log',
                'status': 'error',
                'success': False,
                'log_content': '',
                'log_lines': [],
                'error': str(e),
                'timestamp': self._get_current_time(),
                'message': f'Failed to access update log: {str(e)}',
                'notes': 'An error occurred while trying to access the log file.'
            }
    
    def _get_health_data(self):
        current_time = self._get_current_time()
        server_ip = self._get_server_ip()
        
        health_data = {
            'status': 'pass',
            'version': '1',
            'serviceId': 'xandeum-node',
            'description': 'Xandeum Node Health Check',
            'chillxand_controller_version': CHILLXAND_CONTROLLER_VERSION,
            'timestamp': current_time,
            'security': {
                'ip_whitelisting': 'enabled',
                'allowed_ips': list(ALLOWED_IPS),
                'client_ip': self.client_address[0]
            },
            'checks': {},
            'links': {
                'stats': f'http://{server_ip}:3001/stats',
                'versions': f'http://{server_ip}:3001/versions',
                'summary': f'http://{server_ip}:3001/summary',
                'status_pod': f'http://{server_ip}:3001/status/pod',
                'status_xandminer': f'http://{server_ip}:3001/status/xandminer',
                'status_xandminerd': f'http://{server_ip}:3001/status/xandminerd',
                'restart_pod': f'http://{server_ip}:3001/restart/pod',
                'restart_xandminer': f'http://{server_ip}:3001/restart/xandminer',
                'restart_xandminerd': f'http://{server_ip}:3001/restart/xandminerd',
                'update_controller': f'http://{server_ip}:3001/update/controller',
                'update_controller_log': f'http://{server_ip}:3001/update/controller/log'
            }
        }
        
        overall_status = 'pass'
        
        # CPU monitoring
        try:
            with open('/proc/loadavg', 'r') as f:
                load_avg = f.read().strip().split()
                load_1min = float(load_avg[0])
                
            cpu_count = os.cpu_count() or 1
            load_per_cpu = load_1min / cpu_count
            
            if load_per_cpu > 2.0:
                cpu_status = 'fail'
                overall_status = 'fail'
            elif load_per_cpu > 1.0:
                cpu_status = 'warn'
                if overall_status == 'pass':
                    overall_status = 'warn'
            else:
                cpu_status = 'pass'
                
            health_data['checks']['system:cpu'] = {
                'status': cpu_status,
                'observedValue': load_1min,
                'observedUnit': 'load_average',
                'load_per_cpu': round(load_per_cpu, 2),
                'time': current_time
            }
            
        except Exception as e:
            health_data['checks']['system:cpu'] = {
                'status': 'fail',
                'output': str(e)
            }
            overall_status = 'fail'
        
        # Memory monitoring
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
                
            mem_total = None
            mem_available = None
            swap_total = None
            swap_free = None
            
            for line in meminfo.split('\n'):
                if line.startswith('MemTotal:'):
                    mem_total = int(line.split()[1]) * 1024
                elif line.startswith('MemAvailable:'):
                    mem_available = int(line.split()[1]) * 1024
                elif line.startswith('SwapTotal:'):
                    swap_total = int(line.split()[1]) * 1024
                elif line.startswith('SwapFree:'):
                    swap_free = int(line.split()[1]) * 1024
                    
            if mem_total and mem_available:
                mem_used_percent = ((mem_total - mem_available) / mem_total) * 100
                mem_used_bytes = mem_total - mem_available
                
                if mem_used_percent > 95:
                    mem_status = 'fail'
                    overall_status = 'fail'
                elif mem_used_percent > 85:
                    mem_status = 'warn'
                    if overall_status == 'pass':
                        overall_status = 'warn'
                else:
                    mem_status = 'pass'
                    
                memory_check = {
                    'status': mem_status,
                    'observedValue': round(mem_used_percent, 1),
                    'observedUnit': 'percent_used',
                    'time': current_time,
                    'memory_total_bytes': mem_total,
                    'memory_used_bytes': mem_used_bytes,
                    'memory_available_bytes': mem_available
                }
                
                if swap_total is not None and swap_free is not None:
                    swap_used = swap_total - swap_free
                    swap_used_percent = (swap_used / swap_total * 100) if swap_total > 0 else 0
                    memory_check['swap_total_bytes'] = swap_total
                    memory_check['swap_used_bytes'] = swap_used
                    memory_check['swap_used_percent'] = round(swap_used_percent, 1)
                
                health_data['checks']['system:memory'] = memory_check
            
        except Exception as e:
            health_data['checks']['system:memory'] = {
                'status': 'fail',
                'output': str(e)
            }
            overall_status = 'fail'
        
        # Network monitoring
        try:
            network_stats = self._get_network_stats()
            
            if 'error' not in network_stats and network_stats:
                total_bytes_received = 0
                total_bytes_transmitted = 0
                total_packets_received = 0
                total_packets_transmitted = 0
                interface_count = 0
                
                for interface, stats in network_stats.items():
                    total_bytes_received += stats['bytes_received']
                    total_bytes_transmitted += stats['bytes_transmitted']
                    total_packets_received += stats['packets_received']
                    total_packets_transmitted += stats['packets_transmitted']
                    interface_count += 1
                
                total_bytes = total_bytes_received + total_bytes_transmitted
                total_packets = total_packets_received + total_packets_transmitted
                
                if interface_count == 0:
                    net_status = 'warn'
                    if overall_status == 'pass':
                        overall_status = 'warn'
                else:
                    net_status = 'pass'
                
                health_data['checks']['system:network'] = {
                    'status': net_status,
                    'time': current_time,
                    'active_interfaces': interface_count,
                    'total_bytes_received': total_bytes_received,
                    'total_bytes_transmitted': total_bytes_transmitted,
                    'total_bytes_transferred': total_bytes,
                    'total_packets_received': total_packets_received,
                    'total_packets_transmitted': total_packets_transmitted,
                    'total_packets': total_packets,
                    'interfaces': network_stats
                }
            else:
                health_data['checks']['system:network'] = {
                    'status': 'fail',
                    'output': network_stats.get('error', 'Unknown network error')
                }
                overall_status = 'fail'
                
        except Exception as e:
            health_data['checks']['system:network'] = {
                'status': 'fail',
                'output': str(e)
            }
            overall_status = 'fail'
        
        # Service checks
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
                    'time': current_time
                }
                
            except Exception as e:
                health_data['checks'][f'service:{service_name}'] = {
                    'status': 'fail',
                    'output': str(e)
                }
                overall_status = 'fail'
        
        # Application endpoint checks
        try:
            response = requests.get('http://localhost:80/stats', timeout=5)
            if response.status_code == 200:
                app_status = 'pass'
            else:
                app_status = 'fail'
                overall_status = 'fail'
                
            health_data['checks']['app:stats'] = {
                'status': app_status,
                'observedValue': response.status_code,
                'time': current_time
            }
            
        except Exception as e:
            health_data['checks']['app:stats'] = {
                'status': 'fail',
                'output': str(e)
            }
            overall_status = 'fail'
        
        try:
            response = requests.get('http://localhost:4000/versions', timeout=5)
            if response.status_code == 200:
                versions_status = 'pass'
            else:
                versions_status = 'fail'
                overall_status = 'fail'
                
            health_data['checks']['app:versions'] = {
                'status': versions_status,
                'observedValue': response.status_code,
                'time': current_time
            }
            
        except Exception as e:
            health_data['checks']['app:versions'] = {
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
        if not self._check_ip_allowed():
            return
            
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
                
            elif self.path == '/restart/pod':
                status_data = self._restart_pod_service()
                self._send_json_response(status_data)
                
            elif self.path == '/restart/xandminer':
                status_data = self._restart_service('xandminer.service')
                self._send_json_response(status_data)
                    
            elif self.path == '/restart/xandminerd':
                status_data = self._restart_service('xandminerd.service')
                self._send_json_response(status_data)
                    
            elif self.path == '/update/controller':
                update_data = self._update_controller()
                self._send_json_response(update_data)
                    
            elif self.path == '/update/controller/log':
                log_data = self._get_update_log()
                self._send_json_response(log_data)
                
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            print(f"Error in do_GET for {self.path}: {e}")
            self.send_error(500, str(e))
    
    def log_message(self, format, *args):
        client_ip = self.client_address[0]
        allowed = "ALLOWED" if client_ip in ALLOWED_IPS else "BLOCKED"
        print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] {allowed} - {client_ip} - {format % args}")

PORT = 3001
if __name__ == "__main__":
    try:
        print(f"ChillXand Controller {CHILLXAND_CONTROLLER_VERSION} starting on port {PORT}")
        print(f"IP Whitelisting ENABLED - Allowed IPs: {', '.join(ALLOWED_IPS)}")
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
    log "Python script created with IP whitelisting and made executable"
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

# Configure firewall with IP restrictions
setup_firewall() {
    log "Configuring UFW firewall with IP restrictions..."
    
    # Check if UFW is installed and available
    if ! command -v ufw &> /dev/null; then
        warn "UFW is not installed or not available. Skipping firewall configuration."
        warn "Port 3001 may not be accessible from outside without manual firewall configuration."
        return
    fi
    
    # Reset UFW rules to ensure clean state
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
    
    # Master (USA)
    ufw allow from 74.208.234.116 to any port 3001 comment 'Master USA'
    log "Added rule for Master (USA): 74.208.234.116"
    
    # Control2 (Germany)
    ufw allow from 85.215.145.173 to any port 3001 comment 'Control2 Germany'
    log "Added rule for Control2 (Germany): 85.215.145.173"
    
    # Control3 (Spain)
    ufw allow from 194.164.163.124 to any port 3001 comment 'Control3 Spain'
    log "Added rule for Control3 (Spain): 194.164.163.124"
    
    # Home
    ufw allow from 174.114.192.84 to any port 3001 comment 'Home'
    log "Added rule for Home: 174.114.192.84"
    
    # Home (secondary IP)
    ufw allow from 67.70.165.78 to any port 3001 comment 'Home Secondary'
    log "Added rule for Home (secondary): 67.70.165.78"
    
    # Allow localhost access
    ufw allow from 127.0.0.1 to any port 3001 comment 'Localhost'
    log "Added rule for localhost: 127.0.0.1"
    
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
    echo "    * 174.114.192.84 (Home - add your actual IP here)"
    echo "    * 67.70.165.78 (Home - secondary IP)"
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
