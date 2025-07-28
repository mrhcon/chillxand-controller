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
CHILLXAND_CONTROLLER_VERSION = "{{CHILLXAND_VERSION}}"

# Atlas API Configuration
ATLAS_API_URL = "{{ATLAS_API_URL}}"

UPDATE_STATE_FILE = "/tmp/update-state.json"

# Allowed IP addresses - WHITELIST ONLY
ALLOWED_IPS = {
{{ALLOWED_IPS}}
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

    def _get_server_name(self):
        """Get the server's hostname"""
        try:
            import socket
            return socket.gethostname()
        except Exception:
            return "unknown"

    def _get_server_info(self):
        """Get server IP and hostname"""
        return {
            'ip': self._get_server_ip(),
            'hostname': self._get_server_name()
        }    
        
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
            
    def _check_atlas_registration(self):
        """Check if this server's IP is registered in Atlas"""
        try:
            # Get our server IP using existing function
            server_info = self._get_server_info()
            server_ip = self._get_server_ip()
            
            # Query Atlas API
            response = requests.get(ATLAS_API_URL, timeout=10)
            
            if response.status_code == 200:
                atlas_data = response.json()
                
                # Check if our IP is in the pods list
                # Atlas returns: {"pods": ["ip:port", ...], "pods_count": 109}
                found_pod = None
                found_ip = False
                
                if 'pods' in atlas_data and isinstance(atlas_data['pods'], list):
                    for pod_entry in atlas_data['pods']:
                        # Each entry is in format "ip:port"
                        pod_ip = pod_entry.split(':')[0] if ':' in pod_entry else pod_entry
                        if pod_ip == server_ip:
                            found_pod = pod_entry
                            found_ip = True
                            break
                
                return {
                    'status': 'pass' if found_ip else 'fail',
                    'server_info': server_info,
                    'atlas_url': ATLAS_API_URL,
                    'registered': found_ip,
                    'pod_entry': found_pod,
                    'response_code': response.status_code,
                    'total_pods': atlas_data.get('pods_count', len(atlas_data.get('pods', []))),
                    'time': self._get_current_time()
                }
            else:
                return {
                    'status': 'fail',
                    'server_info': server_info,
                    'atlas_url': ATLAS_API_URL,
                    'registered': False,
                    'response_code': response.status_code,
                    'error': f'Atlas API returned HTTP {response.status_code}',
                    'time': self._get_current_time()
                }
                
        except Exception as e:
            return {
                'status': 'fail',
                'atlas_url': ATLAS_API_URL,
                'registered': False,
                'error': str(e),
                'time': self._get_current_time()
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

    def _get_pod_update_log(self):
        """Get the contents of the pod update log file"""
        try:
            current_time = self._get_current_time()
            
            # Check if log file exists
            log_file = '/tmp/pod-update.log'
            if not os.path.exists(log_file):
                return {
                    'operation': 'get_pod_update_log',
                    'status': 'no_log',
                    'success': True,
                    'log_content': '',
                    'log_lines': [],
                    'file_size': 0,
                    'last_modified': None,
                    'timestamp': current_time,
                    'message': 'No pod update log file found',
                    'notes': 'Pod update log will be created when an update is initiated.'
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
                if 'Pod update completed successfully' in log_content:
                    status = 'completed_success'
                elif 'error' in log_content.lower() or 'failed' in log_content.lower():
                    status = 'completed_error'
                elif log_content.strip():
                    status = 'in_progress'
                else:
                    status = 'empty'
                
                return {
                    'operation': 'get_pod_update_log',
                    'status': status,
                    'success': True,
                    'log_content': log_content,
                    'log_lines': log_lines,
                    'line_count': len(log_lines),
                    'file_size': file_size,
                    'last_modified': last_modified,
                    'timestamp': current_time,
                    'message': f'Pod update log retrieved successfully ({len(log_lines)} lines)',
                    'notes': f'Log file last modified: {last_modified}'
                }
                
            except Exception as read_error:
                return {
                    'operation': 'get_pod_update_log',
                    'status': 'read_error',
                    'success': False,
                    'log_content': '',
                    'log_lines': [],
                    'file_size': file_size,
                    'last_modified': last_modified,
                    'error': str(read_error),
                    'timestamp': current_time,
                    'message': f'Failed to read pod update log: {str(read_error)}',
                    'notes': 'Log file exists but could not be read.'
                }
                
        except Exception as e:
            return {
                'operation': 'get_pod_update_log',
                'status': 'error',
                'success': False,
                'log_content': '',
                'log_lines': [],
                'error': str(e),
                'timestamp': self._get_current_time(),
                'message': f'Failed to access pod update log: {str(e)}',
                'notes': 'An error occurred while trying to access the log file.'
            }
    
    # def _check_connectivity(self):
    #     """Check UDP 5000 public access and localhost TCP ports"""
    #     try:
    #         current_time = self._get_current_time()
    #         server_info = self._get_server_info()
    #         server_ip = self._get_server_ip()
            
    #         results = {
    #             'status': 'pass',
    #             'time': current_time,
    #             'server_info': server_info,
    #             'checks': {}
    #         }
            
    #         # Check UDP 5000 public accessibility
    #         try:
    #             # Check if netcat is available
    #             nc_check = subprocess.run(['which', 'nc'], capture_output=True, timeout=5)
    #             if nc_check.returncode == 0:
    #                 # Test UDP 5000 connectivity
    #                 udp_test = subprocess.run([
    #                     'timeout', '10', 'nc', '-zu', server_ip, '5000'
    #                 ], capture_output=True, timeout=15)
                    
    #                 if udp_test.returncode == 0:
    #                     results['checks']['udp_5000_public'] = {
    #                         'status': 'pass',
    #                         'message': 'UDP 5000 PUBLIC',
    #                         'accessible': True
    #                     }
    #                 else:
    #                     results['checks']['udp_5000_public'] = {
    #                         'status': 'fail',
    #                         'message': 'UDP 5000 NOT PUBLIC',
    #                         'accessible': False
    #                     }
    #                     results['status'] = 'fail'
    #             else:
    #                 results['checks']['udp_5000_public'] = {
    #                     'status': 'warn',
    #                     'message': 'netcat (nc) not installed - cannot test UDP 5000',
    #                     'accessible': 'unknown'
    #                 }
    #                 if results['status'] == 'pass':
    #                     results['status'] = 'warn'
    #         except Exception as e:
    #             results['checks']['udp_5000_public'] = {
    #                 'status': 'fail',
    #                 'message': f'UDP test failed: {str(e)}',
    #                 'accessible': False
    #             }
    #             results['status'] = 'fail'
            
    #         # Check localhost TCP ports 3000 and 4000
    #         localhost_ports = [3000, 4000]
    #         for port in localhost_ports:
    #             try:
    #                 # Use ss command to check if port is listening on localhost
    #                 ss_check = subprocess.run([
    #                     'ss', '-tlnp'
    #                 ], capture_output=True, text=True, timeout=5)
                    
    #                 if ss_check.returncode == 0:
    #                     port_pattern = f'127.0.0.1:{port} '
    #                     if port_pattern in ss_check.stdout:
    #                         results['checks'][f'localhost_tcp_{port}'] = {
    #                             'status': 'pass',
    #                             'message': f'Port {port} listening',
    #                             'listening': True
    #                         }
    #                     else:
    #                         results['checks'][f'localhost_tcp_{port}'] = {
    #                             'status': 'fail',
    #                             'message': f'Port {port} not listening',
    #                             'listening': False
    #                         }
    #                         results['status'] = 'fail'
    #                 else:
    #                     results['checks'][f'localhost_tcp_{port}'] = {
    #                         'status': 'warn',
    #                         'message': f'Cannot check port {port} - ss command failed',
    #                         'listening': 'unknown'
    #                     }
    #                     if results['status'] == 'pass':
    #                         results['status'] = 'warn'
                            
    #             except Exception as e:
    #                 results['checks'][f'localhost_tcp_{port}'] = {
    #                     'status': 'fail',
    #                     'message': f'Port {port} check failed: {str(e)}',
    #                     'listening': False
    #                 }
    #                 results['status'] = 'fail'
            
    #         return results
            
    #     except Exception as e:
    #         return {
    #             'status': 'fail',
    #             'error': str(e),
    #             'time': self._get_current_time()
    #         }

    def _check_connectivity(self):
        """Check UDP 5000 public access using external services and localhost TCP ports"""
        try:
            current_time = self._get_current_time()
            server_info = self._get_server_info()
            server_ip = self._get_server_ip()
            
            results = {
                'status': 'pass',
                'time': current_time,
                'server_info': server_info,
                'checks': {}
            }
            
            overall_status = 'pass'
            
            # Check UDP 5000 public accessibility using external services
            try:
                udp_checks = {}
                
                # 1. Check if port 5000 is bound locally (prerequisite)
                try:
                    ss_check = subprocess.run([
                        'ss', '-ulnp'
                    ], capture_output=True, text=True, timeout=5)
                    
                    if ss_check.returncode == 0:
                        port_listening = ':5000 ' in ss_check.stdout and '0.0.0.0:5000' in ss_check.stdout
                        udp_checks['local_bind'] = {
                            'listening': port_listening,
                            'status': 'pass' if port_listening else 'fail',
                            'bind_address': '0.0.0.0:5000' if port_listening else 'not_found'
                        }
                        if not port_listening:
                            overall_status = 'fail'
                    else:
                        udp_checks['local_bind'] = {
                            'listening': 'unknown',
                            'status': 'warn',
                            'error': 'ss command failed'
                        }
                        if overall_status == 'pass':
                            overall_status = 'warn'
                except Exception as e:
                    udp_checks['local_bind'] = {
                        'listening': False,
                        'status': 'fail',
                        'error': str(e)
                    }
                    overall_status = 'fail'
                
                # 2. External service check using HackerTarget nmap API
                try:
                    import requests
                    
                    # Use HackerTarget's online nmap service
                    api_url = f"https://api.hackertarget.com/nmap/?q={server_ip}"
                    
                    response = requests.get(api_url, timeout=30)
                    
                    if response.status_code == 200:
                        nmap_result = response.text
                        
                        # Look for UDP port 5000 in results
                        if '5000/udp' in nmap_result:
                            if 'open' in nmap_result and '5000/udp' in nmap_result:
                                external_status = 'open'
                                external_accessible = True
                            elif 'filtered' in nmap_result and '5000/udp' in nmap_result:
                                external_status = 'filtered'
                                external_accessible = False
                            else:
                                external_status = 'closed'
                                external_accessible = False
                        else:
                            # If 5000/udp not in results, the service might not scan UDP by default
                            external_status = 'not_scanned'
                            external_accessible = None
                        
                        udp_checks['external_nmap'] = {
                            'service': 'hackertarget.com',
                            'status': 'pass' if external_accessible else 'fail',
                            'port_status': external_status,
                            'accessible': external_accessible,
                            'raw_result': nmap_result[:200] + '...' if len(nmap_result) > 200 else nmap_result
                        }
                        
                        if external_accessible is False:
                            overall_status = 'fail'
                        elif external_accessible is None and overall_status == 'pass':
                            overall_status = 'warn'
                            
                    else:
                        udp_checks['external_nmap'] = {
                            'service': 'hackertarget.com',
                            'status': 'warn',
                            'error': f'HTTP {response.status_code}',
                            'accessible': None
                        }
                        if overall_status == 'pass':
                            overall_status = 'warn'
                            
                except Exception as e:
                    udp_checks['external_nmap'] = {
                        'service': 'hackertarget.com',
                        'status': 'warn',
                        'error': str(e),
                        'accessible': None
                    }
                    if overall_status == 'pass':
                        overall_status = 'warn'
                
                # 3. Alternative external check using portchecker.co
                try:
                    import requests
                    
                    # Use portchecker.co API for UDP testing
                    api_url = f"https://api.portchecker.co/check"
                    params = {
                        'host': server_ip,
                        'port': '5000',
                        'protocol': 'udp'
                    }
                    
                    response = requests.get(api_url, params=params, timeout=20)
                    
                    if response.status_code == 200:
                        try:
                            result = response.json()
                            
                            # Parse the result (API format may vary)
                            if isinstance(result, dict):
                                port_open = result.get('open', False) or result.get('accessible', False)
                                status_msg = result.get('status', 'unknown')
                            else:
                                # Fallback if response is not JSON
                                port_open = 'open' in response.text.lower()
                                status_msg = response.text[:100]
                            
                            udp_checks['external_portchecker'] = {
                                'service': 'portchecker.co',
                                'status': 'pass' if port_open else 'fail',
                                'accessible': port_open,
                                'message': status_msg
                            }
                            
                            if not port_open:
                                overall_status = 'fail'
                                
                        except Exception as parse_error:
                            udp_checks['external_portchecker'] = {
                                'service': 'portchecker.co',
                                'status': 'warn',
                                'error': f'Parse error: {str(parse_error)}',
                                'raw_response': response.text[:200]
                            }
                            if overall_status == 'pass':
                                overall_status = 'warn'
                    else:
                        udp_checks['external_portchecker'] = {
                            'service': 'portchecker.co',
                            'status': 'warn',
                            'error': f'HTTP {response.status_code}',
                            'accessible': None
                        }
                        if overall_status == 'pass':
                            overall_status = 'warn'
                            
                except Exception as e:
                    udp_checks['external_portchecker'] = {
                        'service': 'portchecker.co',
                        'status': 'warn',
                        'error': str(e),
                        'accessible': None
                    }
                    # Don't change overall_status for this optional check
                
                # 4. Local UFW rule verification
                try:
                    ufw_check = subprocess.run([
                        'ufw', 'status'
                    ], capture_output=True, text=True, timeout=5)
                    
                    if ufw_check.returncode == 0:
                        ufw_allows = '5000/udp' in ufw_check.stdout and 'ALLOW' in ufw_check.stdout
                        
                        udp_checks['firewall_rule'] = {
                            'status': 'pass' if ufw_allows else 'fail',
                            'ufw_allows': ufw_allows,
                            'rule_found': '5000/udp' in ufw_check.stdout
                        }
                        
                        if not ufw_allows:
                            overall_status = 'fail'
                    else:
                        udp_checks['firewall_rule'] = {
                            'status': 'warn',
                            'error': 'UFW status check failed'
                        }
                        if overall_status == 'pass':
                            overall_status = 'warn'
                            
                except Exception as e:
                    udp_checks['firewall_rule'] = {
                        'status': 'warn',
                        'error': str(e)
                    }
                    if overall_status == 'pass':
                        overall_status = 'warn'
                
                # Determine overall UDP 5000 status
                local_ok = udp_checks.get('local_bind', {}).get('status') == 'pass'
                firewall_ok = udp_checks.get('firewall_rule', {}).get('status') == 'pass'
                
                # Check if any external service confirms accessibility
                external_accessible = False
                external_services_tried = 0
                external_services_passed = 0
                
                for check_name in ['external_nmap', 'external_portchecker']:
                    check = udp_checks.get(check_name, {})
                    if check.get('accessible') is not None:
                        external_services_tried += 1
                        if check.get('accessible'):
                            external_services_passed += 1
                            external_accessible = True
                
                # Generate final status message
                if local_ok and firewall_ok and external_accessible:
                    udp_status = 'pass'
                    udp_message = "UDP 5000 PUBLIC - Confirmed by external services"
                elif local_ok and firewall_ok and external_services_tried == 0:
                    udp_status = 'warn'
                    udp_message = "UDP 5000 configured correctly - External verification unavailable"
                elif local_ok and firewall_ok:
                    udp_status = 'fail'
                    udp_message = f"UDP 5000 NOT PUBLIC - External services confirm blocking ({external_services_passed}/{external_services_tried} passed)"
                elif not local_ok:
                    udp_status = 'fail'
                    udp_message = "UDP 5000 NOT PUBLIC - Service not bound to public interface"
                elif not firewall_ok:
                    udp_status = 'fail'
                    udp_message = "UDP 5000 NOT PUBLIC - Firewall blocking"
                else:
                    udp_status = 'warn'
                    udp_message = "UDP 5000 status uncertain - Configuration issues detected"
                
                results['checks']['udp_5000_public'] = {
                    'status': udp_status,
                    'message': udp_message,
                    'accessible': udp_status == 'pass',
                    'detailed_checks': udp_checks,
                    'external_services_tried': external_services_tried,
                    'external_services_passed': external_services_passed
                }
                
                if udp_status == 'fail':
                    overall_status = 'fail'
                elif udp_status == 'warn' and overall_status == 'pass':
                    overall_status = 'warn'
                    
            except Exception as e:
                results['checks']['udp_5000_public'] = {
                    'status': 'fail',
                    'message': f'UDP 5000 check failed: {str(e)}',
                    'accessible': False,
                    'error': str(e)
                }
                overall_status = 'fail'
            
            # Check localhost TCP ports 3000 and 4000 (keeping existing logic)
            localhost_ports = [3000, 4000]
            for port in localhost_ports:
                try:
                    ss_check = subprocess.run([
                        'ss', '-tlnp'
                    ], capture_output=True, text=True, timeout=5)
                    
                    if ss_check.returncode == 0:
                        port_pattern = f'127.0.0.1:{port} '
                        if port_pattern in ss_check.stdout:
                            results['checks'][f'localhost_tcp_{port}'] = {
                                'status': 'pass',
                                'message': f'Port {port} listening on localhost',
                                'listening': True
                            }
                        else:
                            results['checks'][f'localhost_tcp_{port}'] = {
                                'status': 'fail',
                                'message': f'Port {port} not listening on localhost',
                                'listening': False
                            }
                            overall_status = 'fail'
                    else:
                        results['checks'][f'localhost_tcp_{port}'] = {
                            'status': 'warn',
                            'message': f'Cannot check port {port} - ss command failed',
                            'listening': 'unknown'
                        }
                        if overall_status == 'pass':
                            overall_status = 'warn'
                            
                except Exception as e:
                    results['checks'][f'localhost_tcp_{port}'] = {
                        'status': 'fail',
                        'message': f'Port {port} check failed: {str(e)}',
                        'listening': False
                    }
                    overall_status = 'fail'
            
            results['status'] = overall_status
            return results
            
        except Exception as e:
            return {
                'status': 'fail',
                'error': str(e),
                'time': self._get_current_time()
            }

    # def _debug_udp_5000(self):
    #     """Comprehensive UDP 5000 debugging with detailed error reporting"""
    #     try:
    #         current_time = self._get_current_time()
    #         server_ip = self._get_server_ip()
            
    #         debug_results = {
    #             'timestamp': current_time,
    #             'server_ip': server_ip,
    #             'checks': {},
    #             'recommendations': []
    #         }
            
    #         # 1. Detailed port binding check
    #         print("=== UDP 5000 DEBUG: Checking port binding ===")
    #         try:
    #             # Check with ss command
    #             ss_result = subprocess.run([
    #                 'ss', '-ulnp', 'sport', '=', '5000'
    #             ], capture_output=True, text=True, timeout=10)
                
    #             debug_results['checks']['port_binding'] = {
    #                 'command': 'ss -ulnp sport = 5000',
    #                 'return_code': ss_result.returncode,
    #                 'stdout': ss_result.stdout,
    #                 'stderr': ss_result.stderr,
    #                 'analysis': {}
    #             }
                
    #             if ss_result.returncode == 0:
    #                 if ss_result.stdout.strip():
    #                     # Port is bound
    #                     lines = ss_result.stdout.strip().split('\n')
    #                     for line in lines[1:]:  # Skip header
    #                         if '5000' in line:
    #                             parts = line.split()
    #                             if len(parts) >= 5:
    #                                 local_addr = parts[4]
    #                                 debug_results['checks']['port_binding']['analysis'] = {
    #                                     'bound': True,
    #                                     'bind_address': local_addr,
    #                                     'status': 'listening'
    #                                 }
                                    
    #                                 # Check if bound to all interfaces or just localhost
    #                                 if local_addr.startswith('0.0.0.0:') or local_addr.startswith('*:'):
    #                                     debug_results['checks']['port_binding']['analysis']['public_bind'] = True
    #                                 elif local_addr.startswith('127.0.0.1:') or local_addr.startswith('localhost:'):
    #                                     debug_results['checks']['port_binding']['analysis']['public_bind'] = False
    #                                     debug_results['recommendations'].append(
    #                                         "Service is bound to localhost only. Change bind address to 0.0.0.0:5000 for public access."
    #                                     )
    #                 else:
    #                     debug_results['checks']['port_binding']['analysis'] = {
    #                         'bound': False,
    #                         'status': 'not_listening'
    #                     }
    #                     debug_results['recommendations'].append(
    #                         "No service is listening on UDP port 5000. Start the UDP service first."
    #                     )
    #             else:
    #                 debug_results['checks']['port_binding']['analysis'] = {
    #                     'bound': 'unknown',
    #                     'error': f"ss command failed with code {ss_result.returncode}"
    #                 }
                    
    #         except Exception as e:
    #             debug_results['checks']['port_binding'] = {
    #                 'error': str(e),
    #                 'status': 'check_failed'
    #             }
            
    #         # 2. Alternative port check using netstat
    #         try:
    #             netstat_result = subprocess.run([
    #                 'netstat', '-ulnp'
    #             ], capture_output=True, text=True, timeout=10)
                
    #             debug_results['checks']['netstat_check'] = {
    #                 'command': 'netstat -ulnp',
    #                 'return_code': netstat_result.returncode,
    #                 'analysis': {}
    #             }
                
    #             if netstat_result.returncode == 0:
    #                 port_5000_lines = [line for line in netstat_result.stdout.split('\n') if ':5000 ' in line]
    #                 debug_results['checks']['netstat_check']['port_5000_entries'] = port_5000_lines
    #                 debug_results['checks']['netstat_check']['analysis']['found_entries'] = len(port_5000_lines)
                
    #         except Exception as e:
    #             debug_results['checks']['netstat_check'] = {
    #                 'error': str(e),
    #                 'note': 'netstat may not be available on this system'
    #             }
            
    #         # 3. Firewall detailed analysis
    #         try:
    #             # Check iptables INPUT chain specifically
    #             iptables_input = subprocess.run([
    #                 'iptables', '-L', 'INPUT', '-n', '--line-numbers'
    #             ], capture_output=True, text=True, timeout=10)
                
    #             debug_results['checks']['firewall_input'] = {
    #                 'command': 'iptables -L INPUT -n --line-numbers',
    #                 'return_code': iptables_input.returncode,
    #                 'stdout': iptables_input.stdout,
    #                 'stderr': iptables_input.stderr,
    #                 'analysis': {}
    #             }
                
    #             if iptables_input.returncode == 0:
    #                 rules = iptables_input.stdout
                    
    #                 # Look for UDP 5000 specific rules
    #                 udp_5000_rules = []
    #                 for line in rules.split('\n'):
    #                     if '5000' in line and 'udp' in line.lower():
    #                         udp_5000_rules.append(line.strip())
                    
    #                 debug_results['checks']['firewall_input']['analysis'] = {
    #                     'udp_5000_rules': udp_5000_rules,
    #                     'rule_count': len(udp_5000_rules)
    #                 }
                    
    #                 # Check default policy
    #                 if 'Chain INPUT (policy DROP' in rules:
    #                     debug_results['checks']['firewall_input']['analysis']['default_policy'] = 'DROP'
    #                     if not udp_5000_rules:
    #                         debug_results['recommendations'].append(
    #                             "Firewall has DROP policy and no explicit UDP 5000 ACCEPT rule. Add: iptables -A INPUT -p udp --dport 5000 -j ACCEPT"
    #                         )
    #                 elif 'Chain INPUT (policy ACCEPT' in rules:
    #                     debug_results['checks']['firewall_input']['analysis']['default_policy'] = 'ACCEPT'
                    
    #             # Check if ufw is active
    #             try:
    #                 ufw_status = subprocess.run([
    #                     'ufw', 'status'
    #                 ], capture_output=True, text=True, timeout=5)
                    
    #                 debug_results['checks']['ufw_status'] = {
    #                     'command': 'ufw status',
    #                     'return_code': ufw_status.returncode,
    #                     'stdout': ufw_status.stdout,
    #                     'active': 'Status: active' in ufw_status.stdout if ufw_status.returncode == 0 else False
    #                 }
                    
    #                 if 'Status: active' in ufw_status.stdout and '5000/udp' not in ufw_status.stdout:
    #                     debug_results['recommendations'].append(
    #                         "UFW is active but no rule for UDP 5000. Add: sudo ufw allow 5000/udp"
    #                     )
                        
    #             except Exception:
    #                 debug_results['checks']['ufw_status'] = {'note': 'ufw not available or not installed'}
                    
    #         except Exception as e:
    #             debug_results['checks']['firewall_input'] = {
    #                 'error': str(e),
    #                 'note': 'iptables check failed - may need root privileges'
    #             }
            
    #         # 4. Network interface analysis
    #         try:
    #             ip_addr_result = subprocess.run([
    #                 'ip', 'addr', 'show'
    #             ], capture_output=True, text=True, timeout=10)
                
    #             if ip_addr_result.returncode == 0:
    #                 interfaces = {}
    #                 current_interface = None
                    
    #                 for line in ip_addr_result.stdout.split('\n'):
    #                     if line and not line.startswith(' '):
    #                         # New interface
    #                         parts = line.split(':')
    #                         if len(parts) >= 2:
    #                             current_interface = parts[1].strip()
    #                             interfaces[current_interface] = {'addresses': []}
    #                     elif current_interface and 'inet ' in line:
    #                         # IP address line
    #                         inet_part = line.strip().split('inet ')[1].split()[0]
    #                         interfaces[current_interface]['addresses'].append(inet_part)
                    
    #                 debug_results['checks']['network_interfaces'] = {
    #                     'interfaces': interfaces,
    #                     'server_ip_found': any(
    #                         server_ip in str(addrs) for addrs in interfaces.values()
    #                     )
    #                 }
                    
    #         except Exception as e:
    #             debug_results['checks']['network_interfaces'] = {
    #                 'error': str(e)
    #             }
            
    #         # 5. Test actual connectivity
    #         try:
    #             # Test with timeout and specific error capture
    #             nc_local_test = subprocess.run([
    #                 'timeout', '3', 'nc', '-v', '-u', '-z', '127.0.0.1', '5000'
    #             ], capture_output=True, text=True, timeout=5)
                
    #             nc_external_test = subprocess.run([
    #                 'timeout', '3', 'nc', '-v', '-u', '-z', server_ip, '5000'
    #             ], capture_output=True, text=True, timeout=5)
                
    #             debug_results['checks']['connectivity_tests'] = {
    #                 'local_test': {
    #                     'command': 'nc -v -u -z 127.0.0.1 5000',
    #                     'return_code': nc_local_test.returncode,
    #                     'stdout': nc_local_test.stdout,
    #                     'stderr': nc_local_test.stderr,
    #                     'success': nc_local_test.returncode == 0
    #                 },
    #                 'external_test': {
    #                     'command': f'nc -v -u -z {server_ip} 5000',
    #                     'return_code': nc_external_test.returncode,
    #                     'stdout': nc_external_test.stdout,
    #                     'stderr': nc_external_test.stderr,
    #                     'success': nc_external_test.returncode == 0
    #                 }
    #             }
                
    #         except Exception as e:
    #             debug_results['checks']['connectivity_tests'] = {
    #                 'error': str(e),
    #                 'note': 'netcat connectivity tests failed'
    #             }
            
    #         # 6. Check for common UDP service processes
    #         try:
    #             # Look for processes that might be using port 5000
    #             lsof_result = subprocess.run([
    #                 'lsof', '-i', ':5000'
    #             ], capture_output=True, text=True, timeout=10)
                
    #             debug_results['checks']['process_check'] = {
    #                 'command': 'lsof -i :5000',
    #                 'return_code': lsof_result.returncode,
    #                 'stdout': lsof_result.stdout,
    #                 'stderr': lsof_result.stderr
    #             }
                
    #             if lsof_result.returncode == 0 and lsof_result.stdout.strip():
    #                 debug_results['checks']['process_check']['analysis'] = {
    #                     'processes_found': True,
    #                     'process_lines': lsof_result.stdout.strip().split('\n')[1:]  # Skip header
    #                 }
    #             else:
    #                 debug_results['checks']['process_check']['analysis'] = {
    #                     'processes_found': False
    #                 }
    #                 debug_results['recommendations'].append(
    #                     "No processes found using port 5000. Check if your UDP service is running."
    #                 )
                    
    #         except Exception as e:
    #             debug_results['checks']['process_check'] = {
    #                 'error': str(e),
    #                 'note': 'lsof command not available or failed'
    #             }
            
    #         # 7. Generate summary and recommendations
    #         debug_results['summary'] = self._analyze_udp_debug_results(debug_results)
            
    #         return debug_results
            
    #     except Exception as e:
    #         return {
    #             'error': str(e),
    #             'timestamp': self._get_current_time(),
    #             'note': 'UDP 5000 debug check failed'
    #         }
    
    # def _analyze_udp_debug_results(self, debug_results):
    #     """Analyze debug results and provide actionable summary"""
    #     summary = {
    #         'overall_status': 'unknown',
    #         'primary_issues': [],
    #         'likely_causes': [],
    #         'next_steps': []
    #     }
        
    #     # Analyze port binding
    #     port_binding = debug_results['checks'].get('port_binding', {}).get('analysis', {})
    #     if port_binding.get('bound') is False:
    #         summary['primary_issues'].append('Service not listening on UDP 5000')
    #         summary['likely_causes'].append('UDP service not started or misconfigured')
    #         summary['next_steps'].append('Start the UDP service and verify it binds to port 5000')
    #         summary['overall_status'] = 'service_not_running'
    #     elif port_binding.get('public_bind') is False:
    #         summary['primary_issues'].append('Service bound to localhost only')
    #         summary['likely_causes'].append('Service configured to bind to 127.0.0.1 instead of 0.0.0.0')
    #         summary['next_steps'].append('Reconfigure service to bind to 0.0.0.0:5000')
    #         summary['overall_status'] = 'localhost_only'
    #     elif port_binding.get('bound') is True and port_binding.get('public_bind') is True:
    #         # Service is bound correctly, check other issues
    #         connectivity_tests = debug_results['checks'].get('connectivity_tests', {})
    #         if connectivity_tests.get('external_test', {}).get('success') is False:
    #             summary['primary_issues'].append('External connectivity blocked')
    #             summary['likely_causes'].append('Firewall or network routing issue')
    #             summary['next_steps'].append('Check firewall rules and network configuration')
    #             summary['overall_status'] = 'network_blocked'
    #         else:
    #             summary['overall_status'] = 'likely_working'
        
    #     # Check firewall issues
    #     firewall_analysis = debug_results['checks'].get('firewall_input', {}).get('analysis', {})
    #     if firewall_analysis.get('default_policy') == 'DROP' and not firewall_analysis.get('udp_5000_rules'):
    #         summary['primary_issues'].append('Firewall blocking UDP 5000')
    #         summary['likely_causes'].append('iptables DROP policy with no UDP 5000 ACCEPT rule')
    #         summary['next_steps'].append('Add firewall rule: iptables -A INPUT -p udp --dport 5000 -j ACCEPT')
        
    #     return summary
    
    # # Add this method to your existing class to get detailed debug info
    # def _get_udp_debug_endpoint(self):
    #     """Endpoint to get detailed UDP 5000 debugging information"""
    #     try:
    #         debug_info = self._debug_udp_5000()
    #         return {
    #             'operation': 'udp_5000_debug',
    #             'success': True,
    #             'debug_results': debug_info,
    #             'timestamp': self._get_current_time()
    #         }
    #     except Exception as e:
    #         return {
    #             'operation': 'udp_5000_debug',
    #             'success': False,
    #             'error': str(e),
    #             'timestamp': self._get_current_time()
    #         }
    
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
            },
            'health': self._get_health_data()            
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
    
    def _update_pod(self):
        """Update the pod using the Xandeum installer with option 2"""
        try:
            current_time = self._get_current_time()
            
            # Build script completely avoiding $(...) patterns during construction
            script_lines = []
            script_lines.append('#!/bin/bash')
            script_lines.append('set -e')
            script_lines.append('sleep 2')
            script_lines.append('')
            script_lines.append('echo "Starting pod update using Xandeum installer..." > /tmp/pod-update.log 2>&1')
            script_lines.append(f'echo "Timestamp: {current_time}" >> /tmp/pod-update.log 2>&1')
            script_lines.append('')
            script_lines.append('cd /tmp')
            
            dollar = '$'
            open_paren = '('
            close_paren = ')'
            
            # Build the working directory command
            working_dir_cmd = f'echo "Working directory: {dollar}{open_paren}pwd{close_paren}" >> /tmp/pod-update.log 2>&1'
            script_lines.append(working_dir_cmd)
            
            script_lines.append('')
            script_lines.append('# Clean up any existing installer files')
            script_lines.append('rm -f install.sh install-*.sh')
            script_lines.append('echo "Cleaned up existing installer files" >> /tmp/pod-update.log 2>&1')
            script_lines.append('')
            script_lines.append('# Download fresh installer')
            script_lines.append('echo "Downloading Xandeum installer..." >> /tmp/pod-update.log 2>&1')
            script_lines.append('wget -O install.sh "https://raw.githubusercontent.com/Xandeum/xandminer-installer/refs/heads/master/install.sh" >> /tmp/pod-update.log 2>&1')
            script_lines.append('')
            script_lines.append('sleep 2')
            script_lines.append('')
            script_lines.append('chmod a+x install.sh')
            script_lines.append('echo "Made installer executable" >> /tmp/pod-update.log 2>&1')
            script_lines.append('')
            script_lines.append('# Run installer with option 2 (Update Xandeum pNode Software)')
            script_lines.append('echo "Running Xandeum installer with option 2 (Update)..." >> /tmp/pod-update.log 2>&1')
            script_lines.append('echo "2" | ./install.sh >> /tmp/pod-update.log 2>&1')
            script_lines.append('')
            script_lines.append('# Clean up installer')
            script_lines.append('rm -f install.sh')
            script_lines.append('echo "Cleaned up installer file" >> /tmp/pod-update.log 2>&1')
            script_lines.append('')
            script_lines.append('echo "Pod update completed successfully" >> /tmp/pod-update.log 2>&1')
            script_lines.append('rm -f /tmp/update-pod.sh')
            
            # Join all lines - no command substitution patterns exist during processing
            final_script = '\n'.join(script_lines)
            
            # Write the final script
            with open('/tmp/update-pod.sh', 'w') as f:
                f.write(final_script)
            
            subprocess.run(['chmod', '+x', '/tmp/update-pod.sh'], timeout=5)
            
            subprocess.Popen([
                'nohup', '/tmp/update-pod.sh'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            
            return {
                'operation': 'pod_update',
                'status': 'update_initiated',
                'success': True,
                'update_process': {
                    'initiated': True,
                    'background_script_created': True,
                    'script_path': '/tmp/update-pod.sh',
                    'log_path': '/tmp/pod-update.log',
                    'installer_url': 'https://raw.githubusercontent.com/Xandeum/xandminer-installer/refs/heads/master/install.sh',
                    'selected_option': '2 (Update Xandeum pNode Software)'
                },
                'timestamp': current_time,
                'message': 'Pod update initiated using Xandeum installer (option 2)',
                'notes': f'Pod update initiated. Monitor at: http://{self._get_server_ip()}:3001/update/pod/log'
            }
            
        except Exception as e:
            return {
                'operation': 'pod_update',
                'status': 'exception',
                'success': False,
                'error': str(e),
                'timestamp': self._get_current_time(),
                'message': f'Pod update endpoint failed: {str(e)}'
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
                
                # Build script completely avoiding $(...) patterns during construction
                script_lines = []
                script_lines.append('#!/bin/bash')
                script_lines.append('set -e')
                script_lines.append('sleep 2')
                script_lines.append('')
                script_lines.append('echo "Starting controller update with callback validation..." > /tmp/update.log 2>&1')
                script_lines.append(f'echo "Current version: {current_version}" >> /tmp/update.log 2>&1')
                script_lines.append(f'echo "Target version: {github_version}" >> /tmp/update.log 2>&1')
                script_lines.append(f'echo "Cache-busting: {cache_bust}" >> /tmp/update.log 2>&1')
                script_lines.append('')
                script_lines.append('cd /tmp')

                dollar = '$'
                open_paren = '('
                close_paren = ')'
                
                # Build the problematic line by concatenating parts - no $() until final assembly
                working_dir_cmd = f'echo "Working directory: {dollar}{open_paren}pwd{close_paren}" >> /tmp/update.log 2>&1'
                script_lines.append(working_dir_cmd)
                
                script_lines.append('')
                script_lines.append('# Clean up any existing files')
                script_lines.append('rm -f install-controller-proxy.sh install-controller-proxy-*.sh')
                script_lines.append('echo "Cleaned up existing files" >> /tmp/update.log 2>&1')
                script_lines.append('')
                script_lines.append('#  Download fresh file')
                script_lines.append('echo "Downloading fresh script..." >> /tmp/update.log 2>&1')
                script_lines.append(f'wget --no-cache --no-cookies --user-agent="ChillXandController/{timestamp}" -O install-controller-proxy.sh "https://raw.githubusercontent.com/mrhcon/chillxand-controller/main/install-controller-proxy.sh?cb={cache_bust}" >> /tmp/update.log 2>&1')
                script_lines.append('')
                script_lines.append('sleep 5')
                script_lines.append('')
                
                # Build grep commands piece by piece to avoid execution
                version_cmd = f'DOWNLOADED_VERSION={dollar}{open_paren}grep \'CHILLXAND_VERSION=\' install-controller-proxy.sh | head -1 | cut -d\'"\' -f2{close_paren}'
                echo_version_cmd = f'echo "Downloaded version: {dollar}DOWNLOADED_VERSION" >> /tmp/update.log 2>&1'
                
                script_lines.append(version_cmd)
                script_lines.append(echo_version_cmd)
                
                script_lines.append('')
                script_lines.append('chmod +x install-controller-proxy.sh')
                script_lines.append('echo "Made file executable" >> /tmp/update.log 2>&1')
                script_lines.append('')
                script_lines.append('# Create marker file before running installer')
                script_lines.append('touch /tmp/update-in-progress')
                script_lines.append('')
                script_lines.append('# Run installer - this will likely terminate our script when service restarts')
                script_lines.append('echo "Running installer (service will restart)..." >> /tmp/update.log 2>&1')
                script_lines.append('./install-controller-proxy.sh >> /tmp/update.log 2>&1')
                script_lines.append('')
                script_lines.append('echo "Installer completed, service should restart automatically" >> /tmp/update.log 2>&1')
                script_lines.append('rm -f /tmp/update-in-progress /tmp/update-controller.sh')
                
                # Join all lines - no command substitution patterns exist during processing
                final_script = '\n'.join(script_lines)
                
                # Write the final script
                with open('/tmp/update-controller.sh', 'w') as f:
                    f.write(final_script)
                
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
        server_info = self._get_server_info()
        server_ip = self._get_server_ip()
        
        health_data = {
            'status': 'pass',
            'versions': self._get_versions_data(), 
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
                'update_pod': f'http://{server_ip}:3001/update/pod',
                'update_controller_log': f'http://{server_ip}:3001/update/controller/log',
                'update_pod_log': f'http://{server_ip}:3001/update/pod/log'
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

        # Check connectivity (UDP 5000 public + localhost TCP ports)
        try:
            connectivity_check = self._check_connectivity()
            health_data['checks']['connectivity'] = connectivity_check
            
            if connectivity_check['status'] == 'fail':
                overall_status = 'fail'
            elif connectivity_check['status'] == 'warn' and overall_status == 'pass':
                overall_status = 'warn'
                
        except Exception as e:
            health_data['checks']['connectivity'] = {
                'status': 'fail',
                'error': str(e),
                'time': current_time
            }
            overall_status = 'fail'        
        
        # Check Atlas registration
        try:
            atlas_check = self._check_atlas_registration()
            health_data['checks']['atlas:registration'] = atlas_check
            
            if atlas_check['status'] == 'fail':
                overall_status = 'fail'
                
        except Exception as e:
            health_data['checks']['atlas:registration'] = {
                'status': 'fail',
                'error': str(e),
                'time': current_time
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
        
        # # Check application endpoints
        # try:
        #     response = requests.get('http://localhost:80/stats', timeout=5)
        #     if response.status_code == 200:
        #         app_status = 'pass'
        #     else:
        #         app_status = 'fail'
        #         overall_status = 'fail'
                
        #     health_data['checks']['app:stats'] = {
        #         'status': app_status,
        #         'observedValue': response.status_code,
        #         'time': current_time
        #     }
            
        # except Exception as e:
        #     health_data['checks']['app:stats'] = {
        #         'status': 'fail',
        #         'output': str(e)
        #     }
        #     overall_status = 'fail'
        
        # try:
        #     response = requests.get('http://localhost:4000/versions', timeout=5)
        #     if response.status_code == 200:
        #         versions_status = 'pass'
        #     else:
        #         versions_status = 'fail'
        #         overall_status = 'fail'
                
        #     health_data['checks']['app:versions'] = {
        #         'status': versions_status,
        #         'observedValue': response.status_code,
        #         'time': current_time
        #     }
            
        # except Exception as e:
        #     health_data['checks']['app:versions'] = {
        #         'status': 'fail',
        #         'output': str(e)
        #     }
        #     overall_status = 'fail'
        
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
                # if health_data['status'] == 'pass':
                #     http_status = 200
                # elif health_data['status'] == 'warn':
                #     http_status = 200
                # else:
                #     http_status = 503
                http_status = 200                
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
            elif self.path == '/update/pod':
                try:
                    update_data = self._update_pod()
                    
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
                        'operation': 'pod_update',
                        'status': 'exception',
                        'return_code': -1,
                        'success': False,
                        'output': f'Endpoint exception: {str(e)}',
                        'stdout': '',
                        'stderr': str(e),
                        'timestamp': self._get_current_time(),
                        'message': f'Pod update endpoint failed: {str(e)}',
                        'notes': 'An exception occurred in the pod update endpoint itself.'
                    }
                    self.send_response(200)  # Still return 200
                    self.send_header('Content-type', 'application/json')
                    self._set_cors_headers()
                    self.end_headers()
                    json_response = json.dumps(error_response, indent=2)
                    self.wfile.write(json_response.encode('utf-8'))    

            elif self.path == '/update/pod/log':
                try:
                    log_data = self._get_pod_update_log()
                    
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
                        'operation': 'get_pod_update_log',
                        'status': 'exception',
                        'success': False,
                        'log_content': '',
                        'log_lines': [],
                        'error': str(e),
                        'timestamp': self._get_current_time(),
                        'message': f'Pod update log endpoint failed: {str(e)}',
                        'notes': 'An exception occurred in the pod update log endpoint.'
                    }
                    self.send_response(200)  # Still return 200
                    self.send_header('Content-type', 'application/json')
                    self._set_cors_headers()
                    self.end_headers()
                    json_response = json.dumps(error_response, indent=2)
                    self.wfile.write(json_response.encode('utf-8'))  

            # elif self.path == '/debug/udp5000':
            #     try:
            #         debug_data = self._get_udp_debug_endpoint()
                    
            #         self.send_response(200)
            #         self.send_header('Content-type', 'application/json')
            #         self._set_cors_headers()
            #         self.end_headers()
                    
            #         json_response = json.dumps(debug_data, indent=2)
            #         self.wfile.write(json_response.encode('utf-8'))
                    
            #     except Exception as e:
            #         error_response = {
            #             'operation': 'udp_5000_debug',
            #             'success': False,
            #             'error': str(e),
            #             'timestamp': self._get_current_time()
            #         }
            #         self.send_response(200)
            #         self.send_header('Content-type', 'application/json')
            #         self._set_cors_headers()
            #         self.end_headers()
            #         json_response = json.dumps(error_response, indent=2)
            #         self.wfile.write(json_response.encode('utf-8'))
            
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
