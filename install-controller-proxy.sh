#!/usr/bin/env python3
import http.server
import socketserver
import requests
import sys
import subprocess
import json
import os
import shutil

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
                "time": subprocess.run(['date', '-u', '+%Y-%m-%dT%H:%M:%SZ'], 
                                     capture_output=True, text=True).stdout.strip()
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
                "time": subprocess.run(['date', '-u', '+%Y-%m-%dT%H:%M:%SZ'], 
                                     capture_output=True, text=True).stdout.strip()
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
                    "time": subprocess.run(['date', '-u', '+%Y-%m-%dT%H:%M:%SZ'], 
                                         capture_output=True, text=True).stdout.strip()
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
                    "time": subprocess.run(['date', '-u', '+%Y-%m-%dT%H:%M:%SZ'], 
                                         capture_output=True, text=True).stdout.strip()
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
                "time": subprocess.run(['date', '-u', '+%Y-%m-%dT%H:%M:%SZ'], 
                                     capture_output=True, text=True).stdout.strip()
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
                "time": subprocess.run(['date', '-u', '+%Y-%m-%dT%H:%M:%SZ'], 
                                     capture_output=True, text=True).stdout.strip()
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
                
        elif self.path == '/health':
            try:
                health_data = self._get_health_data()
                
                # Return appropriate HTTP status based on health
                if health_data['status'] == 'pass':
                    http_status = 200
                elif health_data['status'] == 'warn':
                    http_status = 200  # Some prefer 200 for warnings
                else:  # fail
                    http_status = 503  # Service Unavailable
                
                self.send_response(http_status)
                self.send_header('Content-type', 'application/json')
                self._set_cors_headers()
                self.end_headers()
                
                json_response = json.dumps(health_data, indent=2)
                self.wfile.write(json_response.encode('utf-8'))
                
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
