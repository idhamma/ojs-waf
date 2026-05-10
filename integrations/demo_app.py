#!/usr/bin/env python3
"""
Demo Application - Shows sidecar WAF integration with a simple web app
"""

try:
    from flask import Flask, request, jsonify
except ImportError:
    print("ERROR: Flask not installed")
    print("Install: pip install flask")
    exit(1)

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from others.client_library import WAFClient
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('demo-app')

# ============================================================================
# Initialize Flask with WAF Protection
# ============================================================================

app = Flask(__name__)
waf_client = WAFClient(socket_path="/tmp/waf-agent.sock")

# ============================================================================
# Middleware: WAF Request Checking
# ============================================================================

@app.before_request
def check_with_waf():
    """Check every request with WAF sidecar"""
    
    method = request.method
    uri = request.path
    if request.query_string:
        uri += f"?{request.query_string.decode()}"
    
    headers = dict(request.headers)
    body = request.get_data(as_text=True)
    source_ip = request.remote_addr
    
    # Check with WAF
    result = waf_client.check_request(
        method=method,
        uri=uri,
        headers=headers,
        body=body,
        source_ip=source_ip
    )
    
    # Log
    logger.info(f"{method} {uri} → {result.get('decision')} (score: {result.get('threat_score', 0):.2f})")
    
    # Block if WAF says so
    if result.get('decision') == 'BLOCK':
        return jsonify({
            'error': 'Request blocked by WAF',
            'reason': result.get('attack_type'),
            'threat_score': result.get('threat_score'),
            'timestamp': result.get('timestamp')
        }), 403
    
    # Store result in request context for logging
    request.waf_result = result


# ============================================================================
# API Endpoints
# ============================================================================

@app.route('/api/users', methods=['GET'])
def get_users():
    """Get users (normal endpoint)"""
    return jsonify({
        'users': [
            {'id': 1, 'name': 'Alice', 'email': 'alice@example.com'},
            {'id': 2, 'name': 'Bob', 'email': 'bob@example.com'},
            {'id': 3, 'name': 'Charlie', 'email': 'charlie@example.com'}
        ]
    })


@app.route('/api/users', methods=['POST'])
def create_user():
    """Create new user"""
    data = request.get_json()
    return jsonify({
        'id': 4,
        'name': data.get('name'),
        'email': data.get('email'),
        'created': True
    }), 201


@app.route('/api/search', methods=['GET'])
def search():
    """Search endpoint (vulnerable to various attacks in tests)"""
    query = request.args.get('q', '')
    
    return jsonify({
        'query': query,
        'results': [
            {'title': 'Result 1', 'url': '/page/1'},
            {'title': 'Result 2', 'url': '/page/2'}
        ]
    })


@app.route('/api/comment', methods=['POST'])
def add_comment():
    """Add comment (vulnerable to XSS in tests)"""
    data = request.get_json()
    
    return jsonify({
        'id': 123,
        'comment': data.get('text'),
        'posted': True
    }), 201


@app.route('/download', methods=['GET'])
def download_file():
    """File download endpoint (vulnerable to path traversal in tests)"""
    filepath = request.args.get('file', 'default.txt')
    
    return jsonify({
        'file': filepath,
        'size': 1024,
        'type': 'text/plain'
    })


@app.route('/api/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'waf_enabled': True,
        'waf_socket': '/tmp/waf-agent.sock'
    })


@app.route('/', methods=['GET'])
def index():
    """Landing page"""
    return jsonify({
        'message': 'Demo Web Application with Sidecar WAF',
        'endpoints': {
            '/api/users': ['GET', 'POST'],
            '/api/search': ['GET'],
            '/api/comment': ['POST'],
            '/download': ['GET'],
            '/api/health': ['GET'],
            '/test-attack': ['GET']
        },
        'waf_protection': True
    })


@app.route('/test-attack', methods=['GET'])
def test_attack_endpoint():
    """
    For testing - shows what attacks WAF will block
    Example safe URL (will be allowed):
        /test-attack?type=normal
    
    Example SQL injection (will be blocked):
        /test-attack?type=sqli
    
    Example XSS (will be blocked):
        /test-attack?type=xss
    """
    attack_type = request.args.get('type', 'normal')
    
    test_cases = {
        'normal': {
            'payload': 'SELECT * FROM users',
            'expected': 'ALLOW'
        },
        'sqli': {
            'payload': "SELECT * FROM users WHERE id = 1' OR '1'='1",
            'expected': 'BLOCK'
        },
        'xss': {
            'payload': '<script>alert("XSS")</script>',
            'expected': 'BLOCK'
        },
        'path_traversal': {
            'payload': '../../../../etc/passwd',
            'expected': 'BLOCK'
        }
    }
    
    if attack_type not in test_cases:
        return jsonify({
            'error': 'Unknown attack type',
            'available': list(test_cases.keys())
        }), 400
    
    return jsonify({
        'test': attack_type,
        'payload': test_cases[attack_type]['payload'],
        'expected_result': test_cases[attack_type]['expected'],
        'waf_decision': request.waf_result.get('decision') if hasattr(request, 'waf_result') else 'UNKNOWN',
        'threat_score': request.waf_result.get('threat_score') if hasattr(request, 'waf_result') else 0
    })


# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal server error'}), 500


# ============================================================================
# Startup
# ============================================================================

if __name__ == '__main__':
    print("="*70)
    print("Demo Web Application with Sidecar WAF")
    print("="*70)
    print()
    print("Endpoints:")
    print("  GET  /                - Index/info")
    print("  GET  /api/users       - List users")
    print("  POST /api/users       - Create user")
    print("  GET  /api/search?q=   - Search (queryable)")
    print("  POST /api/comment     - Add comment")
    print("  GET  /download?file=  - Download file")
    print("  GET  /api/health      - Health status")
    print("  GET  /test-attack     - Test attack vectors")
    print()
    print("WAF Protection: ENABLED (via /tmp/waf-agent.sock)")
    print()
    print("Test Commands:")
    print("  # Normal request")
    print("  curl http://localhost:5001/api/users")
    print()
    print("  # SQL Injection (will be blocked)")
    print("  curl http://localhost:5001/api/search?q=SELECT*FROM")
    print()
    print("  # XSS attack (will be blocked)")
    print('  curl -X POST http://localhost:5001/api/comment -H "Content-Type: application/json" -d \'{"text":"<script>"}\'')
    print()
    print("Starting on http://127.0.0.1:5001")
    print("="*70)
    print()
    
    app.run(host='127.0.0.1', port=5001, debug=False)
