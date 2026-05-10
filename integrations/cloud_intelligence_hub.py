#!/usr/bin/env python3
"""
Cloud Intelligence Hub - Central threat intelligence and signature management
Similar to openAppsec cloud backend
"""

import json
import logging
from datetime import datetime
from typing import Dict, List
from collections import defaultdict

try:
    from flask import Flask, request, jsonify
except ImportError:
    print("Flask not installed. Install with: pip install flask")
    exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('cloud-hub')

app = Flask(__name__)

# ============================================================================
# In-Memory Threat Database
# ============================================================================

threat_database = {
    'threats': [],  # Reported threats from agents
    'signatures': {
        'sql_injection': [
            r"(?i)(union|select|insert|update|delete|drop).*(from|where|table)",
            r"(?i)('|\")\s*(or|and)\s*('|\")?=",
            r"(?i)(;|\-\-).*\b(drop|delete|truncate)\b",
        ],
        'xss': [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe",
            r"<svg.*on\w+",
        ],
        'path_traversal': [
            r"\.\./|\.\.\\",
            r"%2e%2e[/\\]",
        ],
        'command_injection': [
            r"[;&|`$()].*\b(cat|ls|rm|wget|curl|bash|sh)\b",
        ]
    },
    'ml_models': {
        'v1': {
            'version': '1.0',
            'accuracy': 0.945,
            'last_updated': datetime.now().isoformat(),
            'training_samples': 50000
        }
    },
    'stats': {
        'total_threats_reported': 0,
        'threats_by_type': defaultdict(int),
        'threats_by_agent': defaultdict(int),
        'threats_by_source_ip': defaultdict(int)
    }
}

# ============================================================================
# API Routes
# ============================================================================

@app.route('/api/v1/threats', methods=['POST'])
def report_threat():
    """
    Receive threat reports from sidecar agents
    
    Expected JSON:
    {
        'session_id': 'abc123',
        'agent_id': 'sidecar-001',
        'timestamp': ISO,
        'request': {'method': 'GET', 'uri': '/...', 'source_ip': '...'},
        'analysis': {'threat_score': 0.95, 'attack_type': 'SQL_INJECTION', ...}
    }
    """
    
    try:
        data = request.get_json()
        
        # Validate token
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if token != 'demo-token':
            return jsonify({'error': 'Unauthorized'}), 401
        
        # Store threat
        threat_record = {
            'id': len(threat_database['threats']),
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        threat_database['threats'].append(threat_record)
        
        # Update statistics
        agent_id = data.get('agent_id', 'unknown')
        attack_type = data.get('analysis', {}).get('attack_type', 'UNKNOWN')
        source_ip = data.get('request', {}).get('source_ip', 'unknown')
        
        threat_database['stats']['total_threats_reported'] += 1
        threat_database['stats']['threats_by_type'][attack_type] += 1
        threat_database['stats']['threats_by_agent'][agent_id] += 1
        threat_database['stats']['threats_by_source_ip'][source_ip] += 1
        
        logger.info(f"[THREAT] {attack_type} from {agent_id} ({source_ip})")
        
        return jsonify({
            'success': True,
            'id': threat_record['id'],
            'message': 'Threat recorded'
        }), 201
    
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({'error': str(e)}), 400


@app.route('/api/v1/signatures', methods=['GET'])
def get_signatures():
    """
    Return latest threat signatures to agents
    Agents fetch these periodically to update their detection
    """
    
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != 'demo-token':
        return jsonify({'error': 'Unauthorized'}), 401
    
    return jsonify({
        'signatures': threat_database['signatures'],
        'version': 1,
        'updated_at': datetime.now().isoformat(),
        'ttl_seconds': 3600
    })


@app.route('/api/v1/ml-model', methods=['GET'])
def get_ml_model():
    """
    Return latest ML model for agents
    In production: would be the actual model weights/checkpoint
    """
    
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != 'demo-token':
        return jsonify({'error': 'Unauthorized'}), 401
    
    return jsonify({
        'models': threat_database['ml_models'],
        'latest_version': '1.0',
        'url': 'http://cloud.example.com/models/v1.tar.gz',
        'checksum': 'sha256:abc123...'
    })


@app.route('/api/v1/threats', methods=['GET'])
def get_threats():
    """Get threat statistics and recent threats"""
    
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != 'demo-token':
        return jsonify({'error': 'Unauthorized'}), 401
    
    limit = request.args.get('limit', 100, type=int)
    
    recent_threats = threat_database['threats'][-limit:]
    
    return jsonify({
        'total_count': len(threat_database['threats']),
        'threats': [{'id': t['id'], 'data': t['data']} for t in recent_threats],
        'statistics': {
            'total_threats_reported': threat_database['stats']['total_threats_reported'],
            'threats_by_type': dict(threat_database['stats']['threats_by_type']),
            'threats_by_agent': dict(threat_database['stats']['threats_by_agent']),
            'top_source_ips': sorted(
                threat_database['stats']['threats_by_source_ip'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }
    })


@app.route('/api/v1/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'threats_recorded': len(threat_database['threats']),
        'agents_connected': len(set(
            t['data'].get('agent_id') 
            for t in threat_database['threats']
        ))
    })


@app.route('/api/v1/dashboard', methods=['GET'])
def dashboard():
    """Dashboard data endpoint"""
    
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token != 'demo-token':
        return jsonify({'error': 'Unauthorized'}), 401
    
    return jsonify({
        'dashboard': {
            'total_threats': threat_database['stats']['total_threats_reported'],
            'threats_by_type': dict(threat_database['stats']['threats_by_type']),
            'threats_by_agent': dict(threat_database['stats']['threats_by_agent']),
            'top_attackers': sorted(
                threat_database['stats']['threats_by_source_ip'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            'last_24h_threats': len([
                t for t in threat_database['threats']
                if True  # In production: check timestamp
            ])
        }
    })


# ============================================================================
# CLI Dashboard
# ============================================================================

def print_dashboard():
    """Print threat dashboard"""
    
    stats = threat_database['stats']
    
    print("\n" + "="*70)
    print("CLOUD INTELLIGENCE HUB - THREAT DASHBOARD")
    print("="*70)
    print(f"Total Threats Reported: {stats['total_threats_reported']}")
    print()
    
    print("Threats by Type:")
    for attack_type, count in sorted(stats['threats_by_type'].items(), key=lambda x: x[1], reverse=True):
        print(f"  - {attack_type}: {count}")
    
    print()
    print("Top Source IPs:")
    for ip, count in sorted(stats['threats_by_source_ip'].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  - {ip}: {count} threats")
    
    print()
    print("Agents:")
    for agent, count in stats['threats_by_agent'].items():
        print(f"  - {agent}: {count} reports")
    
    print()
    print("="*70 + "\n")


# ============================================================================
# Main
# ============================================================================

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description="Cloud Intelligence Hub")
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    
    args = parser.parse_args()
    
    logger.info("="*70)
    logger.info("Cloud Intelligence Hub Started")
    logger.info("="*70)
    logger.info(f"Listening on {args.host}:{args.port}")
    logger.info("API Token: demo-token")
    logger.info("message")
    
    # Start Flask app
    app.run(host=args.host, port=args.port, debug=args.debug)
