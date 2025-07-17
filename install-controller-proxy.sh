#!/bin/bash

# JSON Proxy Service Installation Script
# This script installs and configures the JSON proxy service

# ChillXand Controller Version - Update this for each deployment
CHILLXAND_VERSION="v1.0.152"

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

# # Update system and install dependencies
# install_dependencies() {
#     log "Updating system packages..."
#     # Try multiple approaches for apt-get update
#     if ! apt-get update; then
#         warn "Standard apt-get update failed, trying with --allow-unauthenticated..."
#         if ! apt-get update --allow-unauthenticated; then
#             warn "Apt update with --allow-unauthenticated failed, trying with --allow-releaseinfo-change..."
#             if ! apt-get update --allow-releaseinfo-change; then
#                 warn "All apt-get update attempts failed, continuing anyway..."
#                 warn "Some packages may not be available or up to date"
#             fi
#         fi
#     fi

#     log "Installing required packages..."
#     # Install packages one by one with fallbacks
#     for package in ufw python3 python3-pip net-tools curl; do
#         if ! apt-get install -y "$package"; then
#             warn "Failed to install $package via apt, trying with --allow-unauthenticated..."
#             if ! apt-get install -y --allow-unauthenticated "$package"; then
#                 if [[ "$package" == "net-tools" ]]; then
#                     warn "Failed to install net-tools, will use 'ss' command instead of 'netstat'"
#                 elif [[ "$package" == "ufw" ]]; then
#                     warn "Failed to install ufw, firewall configuration will be skipped"
#                 elif [[ "$package" == "curl" ]]; then
#                     warn "Failed to install curl, endpoint testing will be limited"
#                 else
#                     error "Critical package $package could not be installed"
#                     exit 1
#                 fi
#             fi
#         else
#             log "Successfully installed $package"
#         fi
#     done

#     log "Installing Python requests module..."
#     # Try to install python3-requests via apt-get first (preferred method)
#     if apt-get install -y python3-requests; then
#         log "Successfully installed python3-requests via apt"
#     elif apt-get install -y --allow-unauthenticated python3-requests; then
#         log "Successfully installed python3-requests via apt-get (with --allow-unauthenticated)"
#     else
#         warn "Failed to install python3-requests via apt, trying pip..."
#         # Try different pip installation methods
#         if pip3 install requests; then
#             log "Successfully installed requests via pip3"
#         elif pip3 install --break-system-packages requests; then
#             log "Successfully installed requests via pip3 (with --break-system-packages)"
#         elif python3 -m pip install requests; then
#             log "Successfully installed requests via python3 -m pip"
#         elif python3 -m pip install --break-system-packages requests; then
#             log "Successfully installed requests via python3 -m pip (with --break-system-packages)"
#         else
#             error "Failed to install requests module through all methods"
#             error "Please install python3-requests manually: apt-get install python3-requests"
#             exit 1
#         fi
#     fi
# }

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
from datetime import datetime, timezone

# ChillXand Controller Version
CHILLXAND_CONTROLLER_VERSION = "$CHILLXAND_VERSION"
UPDATE_STATE_FILE = "/tmp/update-state.json"

# Allowed IP addresses - WHITELIST ONLY
ALLOWED_IPS = {
    '74.208.234.116',   # Master (USA)
    '85.215.145.173',   # Control2 (Germany)
    '194.164.163.124',  # Control3 (Spain)
    '174.114.192.84',   # Home
    '67.70.165.78',     # Home #2
    '127.0.0.1',        # Localhost
    '::1'               # IPv6 localhost
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
        # Only set CORS headers for allowed IPs
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
            # Get the IP address by connecting to a remote address
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            # Fallback to localhost if we can't determine IP
            return "localhost"
    
    def _get_current_time(self):
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
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

    def _get_update_log(self):
        """Get the contents of the update log file"""
        try:
            import os
        
            current_time = self._get_current_time()
            
            # Check if log file exists
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
            
            # Get file stats
            stat = os.stat(log_file)
            file_size = stat.st_size
            last_modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%dT%H:%M:%SZ')
            
            # Read the log file
            try:
                with open(log_file, 'r') as f:
                    log_content = f.read()
                
                # Split into lines for easier parsing
                log_lines = log_content.strip().split('\n') if log_content.strip() else []
                
                # Determine status based on log content
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
    
    def _get_cpu_usage(self):
        try:
            # Simplified CPU usage - just return load average for now
            with open('/proc/loadavg', 'r') as f:
                load_avg = f.read().strip().split()
                load_1min = float(load_avg[0])
            return load_1min
        except Exception as e:
            return None
    
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
                        upstream_versions['data']['chillxand_controller'] = CHILLXAND_CONTROLLER_VERSION
                    else:
                        # Add directly to the main object
                        upstream_versions['chillxand_controller'] = CHILLXAND_CONTROLLER_VERSION
                else:
                    # If upstream returned something unexpected, create our own structure
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
    
    def _update_controller(self):
        """Update the controller script from GitHub with callback validation"""
        try:
            current_time = self._get_current_time()
            current_version = CHILLXAND_CONTROLLER_VERSION
    
            # Get latest version from GitHub
            try:
                import subprocess
                import time
                import random
    
                timestamp = str(int(time.time()))          
                random_num = str(random.randint(1, 10000))
                cache_bust = f"{timestamp}_{random_num}"
    
                result = subprocess.run([
                    'curl', '-s', 
                    '-H', 'Cache-Control: no-cache',
                    '-H', 'Pragma: no-cache',
                    f'https://raw.githubusercontent.com/mrhcon/chillxand-controller/main/install-controller-proxy.sh?cb={cache_bust}'
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0 and result.stdout:
                    for line in result.stdout.split('\n'):
                        if 'CHILLXAND_VERSION=' in line and line.strip().startswith('CHILLXAND_VERSION='):
                            github_version = line.split('"')[1] if '"' in line else "unknown"
                            break
                    else:
                        github_version = "unknown"
                else:
                    github_version = "unknown"
                
            except Exception as e:
                github_version = f"error: {str(e)}"                     
            
            update_needed = github_version != current_version and not github_version.startswith("error:")
            
            if github_version.startswith("error:"):
                status = "error_github_check"
                message = f"Could not check GitHub version: {github_version}"
                initiate_update = False
                script_created = False
            elif not update_needed:
                status = "no_update_needed" 
                message = f"Already running latest version ({current_version})"
                initiate_update = False
                script_created = False
            else:
                status = "update_initiated"
                message = f"Update initiated from {current_version} to {github_version}"
                initiate_update = True
                script_created = True
    
            if initiate_update:
                # Save update state before starting
                update_state = {
                    'previous_version': current_version,
                    'target_version': github_version,
                    'update_started': current_time,
                    'cache_bust': cache_bust
                }
                self._save_update_state(update_state)
                
                # Create update script
                update_script = f'''#!/bin/bash
    set -e
    sleep 2
    echo "Starting controller update with callback validation..." > /tmp/update.log 2>&1
    echo "Current version: {current_version}" >> /tmp/update.log 2>&1
    echo "Target version: {github_version}" >> /tmp/update.log 2>&1
    echo "Cache-busting: {cache_bust}" >> /tmp/update.log 2>&1
    
    cd /tmp
    wget --no-cache --no-cookies --user-agent="ChillXandController/{timestamp}" -O install-controller-proxy.sh "https://raw.githubusercontent.com/mrhcon/chillxand-controller/main/install-controller-proxy.sh?cb={cache_bust}" >> /tmp/update.log 2>&1
    
    # Look for CHILLXAND_VERSION
    DOWNLOADED_VERSION=$(head -10 install-controller-proxy.sh | grep 'CHILLXAND_VERSION=' | head -1 | cut -d'"' -f2) 
    echo "Downloaded version: $DOWNLOADED_VERSION" >> /tmp/update.log 2>&1
    
    chmod +x install-controller-proxy.sh
    echo "Running installer (service will restart)..." >> /tmp/update.log 2>&1

    # Create marker file before running installer
    touch /tmp/update-in-progress

    # Run installer - this will likely terminate our script when service restarts
    ./install-controller-proxy.sh >> /tmp/update.log 2>&1
    
    echo "Installer completed, service should restart automatically" >> /tmp/update.log 2>&1
    rm -f /tmp/update-in-progress /tmp/update-controller.sh
    '''
            
                with open('/tmp/update-controller.sh', 'w') as f:
                    f.write(update_script)
                
                subprocess.run(['chmod', '+x', '/tmp/update-controller.sh'], timeout=5)
                
                subprocess.Popen([
                    'nohup', '/tmp/update-controller.sh'
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            
            return {
                'operation': 'controller_update',
                'status': status,
                'success': True,
                'versions': {
                    'current_installed': current_version,
                    'github_latest': github_version,
                    'update_needed': update_needed
                },
                'update_process': {
                    'initiated': initiate_update,
                    'background_script_created': script_created,
                    'script_path': '/tmp/update-controller.sh' if script_created else None,
                    'callback_validation': True
                },
                'timestamp': current_time,
                'message': message,
                'notes': f'Update initiated with callback validation. Service will restart and self-validate. Monitor at: http://{self._get_server_ip()}:3001/update/controller/log' if initiate_update else 'No update process started.'
            }
                            
        except Exception as e:
            return {
                'operation': 'controller_update',
                'status': 'exception',
                'success': False,
                'error': str(e),
                'timestamp': self._get_current_time(),
                'message': f'Update endpoint failed: {str(e)}'
            }        
    def _get_health_data(self):
        # Get basic info first
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
        
        # Simplified CPU monitoring (removed time.sleep that was causing issues)
        try:
            with open('/proc/loadavg', 'r') as f:
                load_avg = f.read().strip().split()
                load_1min = float(load_avg[0])
                
            import os
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
        
        # Enhanced memory monitoring
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
        
        # Network statistics monitoring
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
        
        # Check services for health status
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
        
        # Check application endpoints
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
        # Check IP whitelist first
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
                    
            elif self.path == '/update/controller':
                try:
                    update_data = self._update_controller()
                    
                    # Always return 200 status code
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self._set_cors_headers()
                    self.end_headers()
                    
                    json_response = json.dumps(update_data, indent=2)
                    self.wfile.write(json_response.encode('utf-8'))
                    
                except Exception as e:
                    # Even for exceptions, return 200 with error details
                    error_response = {
                        'operation': 'controller_update',
                        'status': 'exception',
                        'return_code': -1,
                        'success': False,
                        'output': f'Endpoint exception: {str(e)}',
                        'stdout': '',
                        'stderr': str(e),
                        'timestamp': self._get_current_time(),
                        'message': f'Update endpoint failed: {str(e)}',
                        'notes': 'An exception occurred in the update endpoint itself.'
                    }
                    self.send_response(200)  # Still return 200
                    self.send_header('Content-type', 'application/json')
                    self._set_cors_headers()
                    self.end_headers()
                    json_response = json.dumps(error_response, indent=2)
                    self.wfile.write(json_response.encode('utf-8'))
                    
            elif self.path == '/update/controller/log':
                try:
                    log_data = self._get_update_log()
                    
                    # Always return 200 status code
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self._set_cors_headers()
                    self.end_headers()
                    
                    json_response = json.dumps(log_data, indent=2)
                    self.wfile.write(json_response.encode('utf-8'))
                    
                except Exception as e:
                    # Even for exceptions, return 200 with error details
                    error_response = {
                        'operation': 'get_update_log',
                        'status': 'exception',
                        'success': False,
                        'log_content': '',
                        'log_lines': [],
                        'error': str(e),
                        'timestamp': self._get_current_time(),
                        'message': f'Update log endpoint failed: {str(e)}',
                        'notes': 'An exception occurred in the update log endpoint.'
                    }
                    self.send_response(200)  # Still return 200
                    self.send_header('Content-type', 'application/json')
                    self._set_cors_headers()
                    self.end_headers()
                    json_response = json.dumps(error_response, indent=2)
                    self.wfile.write(json_response.encode('utf-8'))               
                
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            print(f"Error in do_GET for {self.path}: {e}")
            self.send_error(500, str(e))
    
    def log_message(self, format, *args):
        # Log requests with IP addresses for security monitoring
        client_ip = self.client_address[0]
        allowed = "ALLOWED" if client_ip in ALLOWED_IPS else "BLOCKED"
        print(f"[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}] {allowed} - {client_ip} - {format % args}")

    def _save_update_state(self, state_data):
        """Save update state to survive restart"""
        try:
            with open(UPDATE_STATE_FILE, 'w') as f:
                json.dump(state_data, f, indent=2)
        except Exception as e:
            print(f"Failed to save update state: {e}")
    
    def _load_update_state(self):
        """Load update state from file"""
        try:
            if os.path.exists(UPDATE_STATE_FILE):
                with open(UPDATE_STATE_FILE, 'r') as f:
                    return json.load(f)
            return None
        except Exception as e:
            print(f"Failed to load update state: {e}")
            return None
    
    def _clear_update_state(self):
        """Clear update state file"""
        try:
            if os.path.exists(UPDATE_STATE_FILE):
                os.remove(UPDATE_STATE_FILE)
        except Exception as e:
            print(f"Failed to clear update state: {e}")
    
    def _append_to_log(self, message):
        """Append message to update log"""
        try:
            timestamp = self._get_current_time()
            with open('/tmp/update.log', 'a') as f:
                f.write(f"[{timestamp}] {message}\n")
        except Exception as e:
            print(f"Failed to write to log: {e}")
    
    def _complete_update_validation(self, update_state):
        """Complete update validation after restart"""
        try:
            self._append_to_log("Service restarted after update, running validation...")
            
            # Check if version actually updated
            version_updated = CHILLXAND_CONTROLLER_VERSION == update_state.get('target_version')
            
            if version_updated:
                self._append_to_log(f"Version update confirmed: {update_state.get('previous_version')} -> {CHILLXAND_CONTROLLER_VERSION}")
            else:
                self._append_to_log(f"WARNING: Version mismatch. Expected: {update_state.get('target_version')}, Got: {CHILLXAND_CONTROLLER_VERSION}")
            
            # Test key endpoints
            endpoint_results = []
            test_endpoints = ['/health', '/stats', '/versions']
            
            for endpoint in test_endpoints:
                try:
                    response = requests.get(f'http://localhost:3001{endpoint}', timeout=5)
                    success = response.status_code == 200
                    endpoint_results.append({
                        'endpoint': endpoint,
                        'status_code': response.status_code,
                        'success': success
                    })
                    if success:
                        self._append_to_log(f"Endpoint test PASSED: {endpoint} (HTTP {response.status_code})")
                    else:
                        self._append_to_log(f"Endpoint test FAILED: {endpoint} (HTTP {response.status_code})")
                except Exception as e:
                    endpoint_results.append({
                        'endpoint': endpoint,
                        'error': str(e),
                        'success': False
                    })
                    self._append_to_log(f"Endpoint test ERROR: {endpoint} - {str(e)}")
            
            # Overall validation result
            all_endpoints_passed = all(result.get('success', False) for result in endpoint_results)
            
            if version_updated and all_endpoints_passed:
                self._append_to_log("Update validation COMPLETED SUCCESSFULLY")
                self._append_to_log("All endpoints responding correctly")
                self._append_to_log("Update process finished")
            elif version_updated:
                self._append_to_log("Update validation COMPLETED WITH WARNINGS")
                self._append_to_log("Version updated but some endpoints failed")
            else:
                self._append_to_log("Update validation FAILED")
                self._append_to_log("Version did not update properly")
            
            # Clear the update state since we're done
            self._clear_update_state()
            
        except Exception as e:
            self._append_to_log(f"Update validation ERROR: {str(e)}")
            self._clear_update_state()

PORT = 3001
if __name__ == "__main__":
    try:
        print(f"ChillXand Controller {CHILLXAND_CONTROLLER_VERSION} starting on port {PORT}")
        print(f"IP Whitelisting ENABLED - Allowed IPs: {', '.join(ALLOWED_IPS)}")
        
        # Check for pending update validation on startup
        update_state = None
        try:
            if os.path.exists(UPDATE_STATE_FILE):
                with open(UPDATE_STATE_FILE, 'r') as f:
                    update_state = json.load(f)
                print(f"Found pending update validation: {update_state.get('previous_version')} -> {update_state.get('target_version')}")
        except Exception as e:
            print(f"Error loading update state: {e}")
        
        # Start the server
        with socketserver.TCPServer(("", PORT), ReadOnlyHandler) as httpd:
            print(f"JSON proxy serving on port {PORT}")
            
            # Complete update validation AFTER server is serving (in a separate thread)
            if update_state:
                print("Scheduling update validation...")
                
                def run_validation():
                    import time
                    import threading
                    
                    # Wait for server to be fully ready
                    time.sleep(5)
                    
                    print("Running update validation...")
                    
                    # Create a temporary handler instance to run validation
                    class TempHandler:
                        def _get_current_time(self):
                            return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                        
                        def _append_to_log(self, message):
                            try:
                                timestamp = self._get_current_time()
                                with open('/tmp/update.log', 'a') as f:
                                    f.write(f"[{timestamp}] {message}\n")
                            except Exception as e:
                                print(f"Failed to write to log: {e}")
                        
                        def _clear_update_state(self):
                            try:
                                if os.path.exists(UPDATE_STATE_FILE):
                                    os.remove(UPDATE_STATE_FILE)
                            except Exception as e:
                                print(f"Failed to clear update state: {e}")
                    
                    temp_handler = TempHandler()
                    temp_handler._append_to_log("Service restarted after update, running validation...")
                    
                    # Check if version actually updated
                    version_updated = CHILLXAND_CONTROLLER_VERSION == update_state.get('target_version')
                    
                    if version_updated:
                        temp_handler._append_to_log(f"Version update confirmed: {update_state.get('previous_version')} -> {CHILLXAND_CONTROLLER_VERSION}")
                        
                        # Test key endpoints now that server is serving
                        endpoint_results = []
                        test_endpoints = ['/health', '/stats', '/versions']
                        
                        for endpoint in test_endpoints:
                            try:
                                response = requests.get(f'http://localhost:3001{endpoint}', timeout=10)
                                success = response.status_code == 200
                                endpoint_results.append({
                                    'endpoint': endpoint,
                                    'status_code': response.status_code,
                                    'success': success
                                })
                                if success:
                                    temp_handler._append_to_log(f"Endpoint test PASSED: {endpoint} (HTTP {response.status_code})")
                                else:
                                    temp_handler._append_to_log(f"Endpoint test FAILED: {endpoint} (HTTP {response.status_code})")
                            except Exception as e:
                                endpoint_results.append({
                                    'endpoint': endpoint,
                                    'error': str(e),
                                    'success': False
                                })
                                temp_handler._append_to_log(f"Endpoint test ERROR: {endpoint} - {str(e)}")
                        
                        # Overall validation result
                        all_endpoints_passed = all(result.get('success', False) for result in endpoint_results)
                        
                        if all_endpoints_passed:
                            temp_handler._append_to_log("Update validation COMPLETED SUCCESSFULLY")
                            temp_handler._append_to_log("All endpoints responding correctly")
                            temp_handler._append_to_log("Update process finished")
                            print("✓ Update validation: SUCCESS")
                        else:
                            temp_handler._append_to_log("Update validation COMPLETED WITH WARNINGS")
                            temp_handler._append_to_log("Version updated but some endpoints failed")
                            print("⚠ Update validation: SUCCESS with warnings")
                    else:
                        temp_handler._append_to_log(f"WARNING: Version mismatch. Expected: {update_state.get('target_version')}, Got: {CHILLXAND_CONTROLLER_VERSION}")
                        temp_handler._append_to_log("Update validation FAILED")
                        temp_handler._append_to_log("Version did not update properly")
                        print("✗ Update validation: FAILED")
                    
                    # Clear the update state since we're done
                    temp_handler._clear_update_state()
                    print("Update validation completed")
                
                # Start validation in background thread
                import threading
                validation_thread = threading.Thread(target=run_validation, daemon=True)
                validation_thread.start()
            
            # Start serving requests (this blocks)
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

    # Home #2
    ufw allow from 67.70.165.78 to any port 3001 comment 'Home'
    log "Added rule for Home #2: 67.70.165.78"
    
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
    setup_firewall
    test_installation
    show_completion_info
}

# Run the main function
main "$@"
