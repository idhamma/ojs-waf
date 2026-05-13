#!/usr/bin/env python3
"""
Nginx Integration Example - Using WAF Client Library
Shows how to integrate with Nginx via reverse proxy or module
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from others.client_library import WAFClient
import json

# ============================================================================
# Nginx Reverse Proxy Integration
# ============================================================================

"""
Nginx Configuration (nginx.conf):
────────────────────────────────────────────────────────────────

upstream waf_agent {
    server 127.0.0.1:8765;  # WAF decision service
    keepalive 32;
}

upstream backend {
    server 192.168.1.100:8080;  # Your actual backend
    keepalive 32;
}

server {
    listen 80;
    server_name www.example.com;
    
    # Request phase: check with WAF
    location / {
        # Forward to WAF agent via subrequest
        access_by_lua_block {
            local client = require("waf_client")
            local result = client.check_request(
                ngx.var.request_method,
                ngx.var.uri,
                ngx.req.get_headers(),
                ngx.var.remote_addr
            )
            
            if result.decision == "BLOCK" then
                return ngx.HTTP_FORBIDDEN
            end
        }
        
        # Forward to backend
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
"""

# ============================================================================
# Python ASGI Middleware for Async Servers
# ============================================================================

class WAFMiddlewareASGI:
    """ASGI middleware for async frameworks (FastAPI, Starlette, etc)"""
    
    def __init__(self, app, socket_path: str = "/tmp/waf-agent.sock"):
        self.app = app
        self.client = WAFClient(socket_path)
    
    async def __call__(self, scope, receive, send):
        """ASGI interface"""
        
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Extract request info
        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        query_string = scope.get("query_string", b"").decode()
        uri = path
        if query_string:
            uri += f"?{query_string}"
        
        # Extract headers
        headers = {
            name.decode(): value.decode() 
            for name, value in scope.get("headers", [])
        }
        
        # Extract body
        body = ""
        try:
            body_parts = []
            while True:
                message = await receive()
                if message["type"] == "http.request":
                    body_parts.append(message.get("body", b""))
                    if not message.get("more_body", False):
                        break
            body = b"".join(body_parts).decode("utf-8", errors="ignore")
        except:
            pass
        
        # Get source IP from scope
        client = scope.get("client")
        remote_addr = client[0] if client else "127.0.0.1"
        
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
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [[b"content-type", b"application/json"]],
            })
            
            response_body = json.dumps({
                'error': 'Request blocked by WAF',
                'threat_score': result.get('threat_score'),
                'attack_type': result.get('attack_type')
            }).encode()
            
            await send({
                "type": "http.response.body",
                "body": response_body,
            })
            return
        
        # Continue with app
        await self.app(scope, receive, send)


# ============================================================================
# FastAPI Example
# ============================================================================

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    
    def create_fastapi_waf(app: FastAPI, socket_path: str = "/tmp/waf-agent.sock"):
        """Add WAF protection to FastAPI app"""
        
        client = WAFClient(socket_path)
        
        @app.middleware("http")
        async def waf_middleware(request: Request, call_next):
            # Extract request data
            method = request.method
            uri = request.url.path
            if request.url.query:
                uri += f"?{request.url.query}"
            
            headers = dict(request.headers)
            source_ip = request.client.host if request.client else "127.0.0.1"
            
            # Read body
            body = await request.body()
            body_str = body.decode("utf-8", errors="ignore")
            
            # Check with WAF
            result = client.check_request(
                method=method,
                uri=uri,
                headers=headers,
                body=body_str,
                source_ip=source_ip
            )
            
            # Block if necessary
            if result.get('decision') == 'BLOCK':
                return JSONResponse(
                    status_code=403,
                    content={
                        'error': 'Request blocked by WAF',
                        'threat_score': result.get('threat_score'),
                        'attack_type': result.get('attack_type')
                    }
                )
            
            # Continue
            return await call_next(request)
        
        return app

except ImportError:
    pass


# ============================================================================
# Demo / Usage Examples
# ============================================================================

def demo_nginx_integration():
    """Demo: Check requests as they would come from Nginx"""
    
    client = WAFClient()
    
    print("="*70)
    print("NGINX INTEGRATION DEMO")
    print("="*70)
    print()
    
    # Simulated requests from Nginx
    requests_to_check = [
        {
            'name': 'Normal API Request',
            'method': 'GET',
            'uri': '/api/v1/users',
            'headers': {
                'Host': 'api.example.com',
                'User-Agent': 'Mozilla/5.0'
            },
            'source_ip': '192.168.1.100'
        },
        {
            'name': 'SQL Injection Attack',
            'method': 'GET',
            'uri': "/api/search?q=admin' UNION SELECT password FROM users--",
            'headers': {
                'Host': 'api.example.com',
                'User-Agent': 'curl/7.64'
            },
            'source_ip': '10.0.0.50'
        },
        {
            'name': 'XSS Attack',
            'method': 'POST',
            'uri': '/api/comments',
            'headers': {
                'Host': 'api.example.com',
                'Content-Type': 'application/json'
            },
            'body': '{"text": "<img src=x onerror=alert(1)>"}',
            'source_ip': '10.0.0.51'
        },
        {
            'name': 'Path Traversal',
            'method': 'GET',
            'uri': '/download?file=../../../../etc/passwd',
            'headers': {
                'User-Agent': 'curl'
            },
            'source_ip': '10.0.0.52'
        }
    ]
    
    for req_test in requests_to_check:
        print(f"\n[TEST] {req_test['name']}")
        print(f"  Method: {req_test['method']} {req_test['uri']}")
        print(f"  Source: {req_test['source_ip']}")
        
        result = client.check_request(
            method=req_test['method'],
            uri=req_test['uri'],
            headers=req_test['headers'],
            body=req_test.get('body', ''),
            source_ip=req_test['source_ip']
        )
        
        print(f"  Decision: {result.get('decision')}")
        print(f"  Threat Score: {result.get('threat_score', 0):.3f}")
        print(f"  Attack Type: {result.get('attack_type', 'NONE')}")
    
    print("\n" + "="*70 + "\n")


if __name__ == '__main__':
    demo_nginx_integration()
