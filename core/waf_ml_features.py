#!/usr/bin/env python3
"""
Feature Extractor for ML-based WAF
Mengextract 20+ numerical features dari HTTP request untuk Random Forest
"""

import numpy as np
import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, List

class FeatureExtractor:
    """Extract numerical features dari HTTP requests untuk ML model"""
    
    def __init__(self):
        self.feature_names = [
            'uri_length',                      # 0
            'uri_special_chars_count',         # 1
            'uri_encoding_ratio',              # 2
            'uri_entropy',                     # 3
            'header_count',                    # 4
            'body_size',                       # 5
            'body_entropy',                    # 6
            'dots_in_uri',                     # 7
            'slashes_in_uri',                  # 8
            'quotes_in_uri',                   # 9
            'semicolons_in_uri',               # 10
            'equals_in_uri',                   # 11
            'parentheses_in_uri',              # 12
            'keywords_dangerous',              # 13
            'sql_like_patterns',               # 14
            'xss_like_patterns',               # 15
            'command_injection_patterns',      # 16
            'path_traversal_patterns',         # 17
            'user_agent_suspicious',           # 18
            'headers_suspicious'               # 19
        ]
    
    @staticmethod
    def entropy(data: str) -> float:
        """Calculate Shannon entropy of string (0-8 range)"""
        if not data:
            return 0.0
        
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        data_len = len(data)
        for count in freq.values():
            p = count / data_len
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
    
    def extract_features(self, request_data: Dict) -> np.ndarray:
        """
        Extract feature vector from HTTP request
        
        Args:
            request_data: Dict with keys: method, uri, headers, body, source_ip
            
        Returns:
            numpy array dengan 20 features (normalized 0-1)
        """
        
        uri = request_data.get('uri', '')
        body = request_data.get('body', '')
        headers = request_data.get('headers', {})
        method = request_data.get('method', '')
        
        features = {}
        
        # ==================== 1. URI FEATURES ====================
        
        # 0. URI length (normalize max 2000 chars = suspicious)
        features['uri_length'] = min(len(uri) / 2000.0, 1.0)
        
        # 1. Special characters in URI
        special_chars = len(re.findall(r'[%;\'"\-\(\)\[\]\{\}]', uri))
        features['uri_special_chars_count'] = min(special_chars / 50.0, 1.0)
        
        # 2. URL encoding ratio (% decoding)
        encoded_chars = len(re.findall(r'%[0-9a-f]{2}', uri, re.I))
        features['uri_encoding_ratio'] = min(encoded_chars / max(len(uri), 1), 1.0)
        
        # 3. URI entropy (higher = more random = suspicious)
        features['uri_entropy'] = self.entropy(uri) / 8.0
        
        # ==================== 2. HEADER FEATURES ====================
        
        # 4. Header count (normalize max 50)
        features['header_count'] = min(len(headers) / 50.0, 1.0)
        
        # ==================== 3. BODY FEATURES ====================
        
        # 5. Body size (normalize max 10MB)
        features['body_size'] = min(len(body) / (10 * 1024 * 1024), 1.0)
        
        # 6. Body entropy
        features['body_entropy'] = self.entropy(body) / 8.0
        
        # ==================== 4. CHARACTER COUNT FEATURES ====================
        
        # 7. Dots in URI (used in path traversal)
        features['dots_in_uri'] = min(uri.count('.') / 10.0, 1.0)
        
        # 8. Slashes in URI (path depth)
        features['slashes_in_uri'] = min(uri.count('/') / 20.0, 1.0)
        
        # 9. Quotes in URI (SQL injection indicator)
        features['quotes_in_uri'] = float('"' in uri or "'" in uri)
        
        # 10. Semicolons in URI (command separator)
        features['semicolons_in_uri'] = float(';' in uri)
        
        # 11. Equals in URI (assignment/parameter)
        features['equals_in_uri'] = min(uri.count('=') / 10.0, 1.0)
        
        # 12. Parentheses in URI (function calls)
        features['parentheses_in_uri'] = float('(' in uri or ')' in uri)
        
        # ==================== 5. PATTERN MATCHING FEATURES ====================
        
        full_text = (uri + body).lower()
        
        # 13. SQL keywords count (DANGEROUS)
        sql_keywords = [
            'union', 'select', 'insert', 'update', 'delete', 'drop',
            'create', 'alter', 'exec', 'execute', 'from', 'where',
            'table', 'and', 'or', 'having', 'bulk', 'truncate'
        ]
        sql_count = sum(1 for kw in sql_keywords if re.search(r'\b' + kw + r'\b', full_text))
        features['keywords_dangerous'] = min(sql_count / 10.0, 1.0)
        
        # 14. SQL-like patterns (regex matching)
        sql_patterns = [
            r"('|\")\s*(or|and)\s*('|\")?\s*=",  # ' OR ' = 
            r"(union\s+all|select\s+\*)",         # UNION ALL
            r"(\-\-|/\*|#).*?(drop|delete|exec)", # Comments with dangerous keywords
            r"(xp_|sp_)\w+",                      # SQL Server extended stored procs
        ]
        sql_matches = sum(1 for p in sql_patterns if re.search(p, full_text, re.I))
        features['sql_like_patterns'] = min(sql_matches / 5.0, 1.0)
        
        # 15. XSS patterns
        xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on(load|error|click|mouseover|focus)\s*=",
            r"<iframe[^>]*>",
            r"<svg[^>]*\s+on\w+",
            r"eval\s*\(",
        ]
        xss_matches = sum(1 for p in xss_patterns if re.search(p, full_text, re.I))
        features['xss_like_patterns'] = min(xss_matches / 6.0, 1.0)
        
        # 16. Command injection patterns
        cmd_patterns = [
            r"[;&|`\n]",                                    # Command separators
            r"\$\(.*?(cat|ls|rm|wget|curl|bash|sh)\b",    # $() execution
            r"`.*?(cat|ls|rm|wget|curl|bash|sh)\b",        # Backtick execution
        ]
        cmd_matches = sum(1 for p in cmd_patterns if re.search(p, full_text, re.I))
        features['command_injection_patterns'] = min(cmd_matches / 5.0, 1.0)
        
        # 17. Path traversal patterns
        traversal_patterns = [
            r"(\.\./|\.\.\\)",                   # ../ atau ..\
            r"(%2e%2e[/\\])",                    # %2e%2e URL encoded
            r"(c:\\|/etc/|/sys/|/proc/)",        # System paths
        ]
        traversal_matches = sum(1 for p in traversal_patterns if re.search(p, full_text, re.I))
        features['path_traversal_patterns'] = min(traversal_matches / 3.0, 1.0)
        
        # ==================== 6. BEHAVIORAL FEATURES ====================
        
        # 18. Suspicious User-Agent
        user_agent = headers.get('User-Agent', '').lower()
        suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan', 'metasploit', 'burp', 'zaproxy']
        features['user_agent_suspicious'] = float(any(agent in user_agent for agent in suspicious_agents))
        
        # 19. Suspicious headers
        suspicious_headers = {
            'x-forwarded-for': 0.1,          # Proxy bypass attempt
            'x-original-url': 0.2,           # Path traversal attempt
            'x-rewrite-url': 0.2,            # URL rewrite bypass
            'x-http-method-override': 0.1,   # Method override
        }
        suspicious_score = sum(
            suspicious_headers.get(h.lower(), 0) 
            for h in headers.keys()
        )
        features['headers_suspicious'] = min(suspicious_score, 1.0)
        
        # Convert to numpy array dalam urutan yang benar
        feature_vector = np.array([
            features[name] for name in self.feature_names
        ], dtype=np.float32)
        
        return feature_vector
    
    def print_features(self, request_data: Dict):
        """Debug: print extracted features"""
        
        features_dict = dict(zip(
            self.feature_names,
            self.extract_features(request_data)
        ))
        
        print("\n" + "="*60)
        print("Feature Extraction Debug")
        print("="*60)
        
        for name, value in features_dict.items():
            severity = "🔴" if value > 0.7 else "🟡" if value > 0.3 else "🟢"
            print(f"{severity} {name:.<35} {value:.4f}")
        
        print("="*60)


# ============================================================================
# Test & Demo
# ============================================================================

if __name__ == '__main__':
    extractor = FeatureExtractor()
    
    print("[*] Feature Extractor for ML-based WAF")
    print(f"[*] Total features: {len(extractor.feature_names)}\n")
    
    # Test 1: Clean request
    clean_request = {
        'method': 'GET',
        'uri': '/api/users?limit=10',
        'headers': {'User-Agent': 'Mozilla/5.0'},
        'body': '',
        'source_ip': '192.168.1.100'
    }
    
    print("[TEST 1] Clean Request")
    features = extractor.extract_features(clean_request)
    extractor.print_features(clean_request)
    print(f"Feature vector size: {features.shape}")
    print(f"Mean threat score: {np.mean(features):.4f}\n")
    
    # Test 2: SQL Injection
    sql_injection = {
        'method': 'GET',
        'uri': "/api/search?q=SELECT*FROM users WHERE id='1' OR '1'='1",
        'headers': {'User-Agent': 'Mozilla'},
        'body': '',
        'source_ip': '10.0.0.1'
    }
    
    print("[TEST 2] SQL Injection Attack")
    features = extractor.extract_features(sql_injection)
    extractor.print_features(sql_injection)
    print(f"Mean threat score: {np.mean(features):.4f}\n")
    
    # Test 3: XSS Attack
    xss_attack = {
        'method': 'POST',
        'uri': '/api/comment',
        'headers': {'Content-Type': 'application/json'},
        'body': '{"text":"<script>alert(\'XSS\')</script>"}',
        'source_ip': '10.0.0.2'
    }
    
    print("[TEST 3] XSS Attack")
    features = extractor.extract_features(xss_attack)
    extractor.print_features(xss_attack)
    print(f"Mean threat score: {np.mean(features):.4f}\n")
    
    # Test 4: Path Traversal
    path_traversal = {
        'method': 'GET',
        'uri': '/download?file=../../../../etc/passwd',
        'headers': {'User-Agent': 'curl'},
        'body': '',
        'source_ip': '10.0.0.3'
    }
    
    print("[TEST 4] Path Traversal Attack")
    features = extractor.extract_features(path_traversal)
    extractor.print_features(path_traversal)
    print(f"Mean threat score: {np.mean(features):.4f}\n")
