#!/usr/bin/env python3
"""
Client Library - For applications to communicate with sidecar WAF agent
"""

import json
import socket
import os
from typing import Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger('waf-client')

class WAFClient:
    """Client to communicate with sidecar WAF agent via Unix socket"""
    
    def __init__(self, socket_path: str = "/tmp/waf-agent.sock"):
        self.socket_path = socket_path
        self.timeout = 5
        
    def check_request(self, 
                     method: str, 
                     uri: str, 
                     headers: Dict = None,
                     body: str = "",
                     source_ip: str = "127.0.0.1") -> Dict:
        """
        Check HTTP request with WAF agent
        
        Returns:
            {
                'decision': 'ALLOW' | 'BLOCK' | 'CHALLENGE',
                'threat_score': 0.0-1.0,
                'confidence': 0.0-1.0,
                'attack_type': 'SQL_INJECTION' | 'XSS' | etc,
                'timestamp': ISO timestamp
            }
        """
        
        if not headers:
            headers = {}
        
        # Prepare request
        request = {
            'method': method,
            'uri': uri,
            'headers': headers,
            'body': body,
            'source_ip': source_ip,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Connect to socket
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
            
            # Send request
            sock.sendall(json.dumps(request).encode('utf-8'))
            
            # Receive response
            response_data = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                except socket.timeout:
                    break
            
            sock.close()
            
            if not response_data:
                return {'decision': 'ALLOW', 'error': 'No response from agent'}
            
            response = json.loads(response_data.decode('utf-8'))
            return response
            
        except FileNotFoundError:
            logger.error(f"Socket not found: {self.socket_path}")
            return {
                'decision': 'ALLOW',
                'error': 'WAF agent not running'
            }
        except Exception as e:
            logger.error(f"Communication error: {e}")
            return {
                'decision': 'ALLOW',
                'error': str(e)
            }


# ============================================================================
# Middleware for Flask/Django
# ============================================================================

class WAFMiddleware:
    """WSGI middleware for WAF request checking"""
    
    def __init__(self, app, socket_path: str = "/tmp/waf-agent.sock"):
        self.app = app
        self.client = WAFClient(socket_path)
    
    def __call__(self, environ, start_response):
        """WSGI interface"""
        
        # Extract request info
        method = environ.get('REQUEST_METHOD', 'GET')
        uri = environ.get('PATH_INFO', '/')
        if environ.get('QUERY_STRING'):
            uri += f"?{environ.get('QUERY_STRING')}"
        
        # Extract headers
        headers = {}
        for key, value in environ.items():
            if key.startswith('HTTP_'):
                header_name = key[5:].replace('_', '-')
                headers[header_name] = value
        
        # Extract body
        body = ""
        if method in ['POST', 'PUT', 'PATCH']:
            try:
                content_length = int(environ.get('CONTENT_LENGTH', 0))
                if content_length > 0:
                    body = environ['wsgi.input'].read(content_length).decode('utf-8', errors='ignore')
            except:
                pass
        
        remote_addr = environ.get('REMOTE_ADDR', '127.0.0.1')
        
        # Check with WAF
        result = self.client.check_request(
            method=method,
            uri=uri,
            headers=headers,
            body=body,
            source_ip=remote_addr
        )
        
        # Block if necessary
        if result.get('decision') == 'BLOCK':
            start_response('403 Forbidden', [('Content-Type', 'application/json')])
            return [json.dumps({
                'error': 'Request blocked by WAF',
                'threat_score': result.get('threat_score'),
                'attack_type': result.get('attack_type')
            }).encode('utf-8')]
        
        # Continue with app
        return self.app(environ, start_response)


# ============================================================================
# Flask Integration
# ============================================================================

try:
    from flask import Flask, request, jsonify, abort
    
    def create_flask_waf(app: Flask, socket_path: str = "/tmp/waf-agent.sock"):
        """Add WAF protection to Flask app"""
        
        client = WAFClient(socket_path)
        
        @app.before_request
        def waf_check():
            method = request.method
            uri = request.path
            if request.query_string:
                uri += f"?{request.query_string.decode()}"
            
            headers = dict(request.headers)
            body = request.get_data(as_text=True, cache=False)
            source_ip = request.remote_addr
            
            result = client.check_request(
                method=method,
                uri=uri,
                headers=headers,
                body=body,
                source_ip=source_ip
            )
            
            if result.get('decision') == 'BLOCK':
                return jsonify({
                    'error': 'Request blocked by WAF',
                    'threat_score': result.get('threat_score'),
                    'attack_type': result.get('attack_type')
                }), 403
        
        return app

except ImportError:
    pass


# ============================================================================
# Test Client
# ============================================================================

def test_client():
    """Test WAF client"""
    
    client = WAFClient()
    
    # Test 1: Normal request
    print("[*] Testing normal request...")
    result = client.check_request(
        method='GET',
        uri='/api/users',
        headers={'User-Agent': 'Mozilla/5.0'},
        source_ip='192.168.1.100'
    )
    print(f"Result: {json.dumps(result, indent=2)}\n")
    
    # Test 2: SQL injection attack
    print("[*] Testing SQL injection...")
    result = client.check_request(
        method='GET',
        uri="/api/users?id=1' OR '1'='1",
        headers={'User-Agent': 'curl/7.64'},
        source_ip='192.168.1.100'
    )
    print(f"Result: {json.dumps(result, indent=2)}\n")
    
    # Test 3: XSS attack
    print("[*] Testing XSS...")
    result = client.check_request(
        method='POST',
        uri='/api/comment',
        headers={'Content-Type': 'application/json'},
        body='{"comment": "<script>alert(1)</script>"}',
        source_ip='192.168.1.100'
    )
    print(f"Result: {json.dumps(result, indent=2)}\n")
    
    # Test 4: Path traversal
    print("[*] Testing path traversal...")
    result = client.check_request(
        method='GET',
        uri='/api/file?path=../../../../etc/passwd',
        headers={'User-Agent': 'curl'},
        source_ip='192.168.1.100'
    )
    print(f"Result: {json.dumps(result, indent=2)}\n")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    test_client()
