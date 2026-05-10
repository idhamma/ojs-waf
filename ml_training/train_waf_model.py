import os
from typing import List, Dict
import re
import numpy as np
import pandas as pd
import pickle
import math
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


def calculate_entropy(data_string):
    """Calculates the Shannon entropy of a string."""
    if not data_string:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data_string.count(chr(x))) / len(data_string)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_features(method, uri, query_string, body="", headers="", stateful_req_rate=0.0):
    """
    Extracts 25 numerical features from raw HTTP components (method, URI, query, body, headers, state).
    These features must map exactly to how the sidecar agent extracts them.
    """
    full_payload = uri + " " + body + " " + headers
    
    # Feature 1-4: Lengths
    uri_len = len(uri)
    body_len = len(body)
    header_len = len(headers)
    full_len = len(full_payload)
    
    # Feature 5: Entropy of payload
    entropy = calculate_entropy(full_payload)
    
    # Feature 6-9: Character Distribution
    num_special_chars = len(re.findall(r'[^a-zA-Z0-9\s]', full_payload))
    num_quotes = full_payload.count("'") + full_payload.count('"')
    num_slashes = uri.count("/") + full_payload.count("\\")
    pct_encoded = full_payload.count('%') / full_len if full_len > 0 else 0
    
    # Feature 10-13: Attack Patterns (Signature hits as features)
    sql_keywords = len(re.findall(r'(?i)\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|AND|OR|WHERE)\b', full_payload))
    xss_patterns = len(re.findall(r'(?i)(<script>|javascript:|onerror=|onload=|eval\()', full_payload))
    path_traversal = len(re.findall(r'(\.\./|\.\.\\)', full_payload))
    command_inj = len(re.findall(r'(;|\&\&|\|\||`|\$\()', full_payload))
    
    # Feature 14-15: OJS Specific Context
    # OJS heavily uses /index.php/journal/... and parameters like ?query=
    has_ojs_structure = 1 if "index.php" in uri else 0
    ojs_param_abuse = 1 if "query=" in uri and num_special_chars > 5 else 0

    # 1. HTTP Method features (Feature 16-17)
    method_upper = method.upper() if method else "GET"
    is_risky_method = 1 if method_upper in ["TRACE", "TRACK", "CONNECT", "PROPFIND", "PUT"] else 0
    is_post = 1 if method_upper == "POST" else 0
    
    # 2. Query anomalies (Feature 18-20)
    query_params_count = query_string.count("&") + 1 if query_string else 0
    if query_string and '=' in query_string:
        parts = query_string.split('&')
        lengths = [len(p.split('=', 1)[1]) if '=' in p else 0 for p in parts]
        max_param_length = max(lengths) if lengths else 0
    else:
        max_param_length = 0
    query_entropy = calculate_entropy(query_string)

    # 3. Header anomalies (Feature 21-23)
    headers_lower = headers.lower() if headers else ""
    missing_user_agent = 1 if "user-agent:" not in headers_lower else 0
    missing_host_header = 1 if "host:" not in headers_lower else 0
    
    user_agent_match = re.search(r'(?i)user-agent:\s*([^\r\n]*)', headers)
    user_agent_length = len(user_agent_match.group(1).strip()) if user_agent_match else 0
    
    # 4. Payload features (Feature 24)
    body_non_ascii = len(re.findall(r'[^\x00-\x7F]', body)) if body else 0
    body_non_ascii_ratio = body_non_ascii / len(body) if len(body) > 0 else 0
    
    # 5. Stateful feature (Feature 25)
    req_rate = float(stateful_req_rate)

    return [
        uri_len, body_len, header_len, full_len, entropy,
        num_special_chars, num_quotes, num_slashes, pct_encoded,
        sql_keywords, xss_patterns, path_traversal, command_inj,
        has_ojs_structure, ojs_param_abuse,
        is_risky_method, is_post, query_params_count, max_param_length, query_entropy,
        missing_user_agent, missing_host_header, user_agent_length, body_non_ascii_ratio, req_rate
    ]

def generate_synthetic_dataset():
    """Generates synthetic dataset targeting Open Journal Systems."""
    print("[*] Generating synthetic dataset for OJS...")
    data = []

    # 1. NORMAL OJS TRAFFIC
    normal_uris = [
        "/index.php/testjournal/index",
        "/index.php/testjournal/article/view/123",
        "/index.php/testjournal/search?query=science",
        "/lib/pkp/styles/pkp.css",
        "/index.php/testjournal/user/register",
        "/index.php/testjournal/about"
    ]
    for _ in range(2500):
        # FIXED
        uri = np.random.choice(normal_uris)
        query_string = ""
        if "?" in uri:
            _, _, query_string = uri.partition("?")
            uri += f"&page={np.random.randint(1, 10)}"
            query_string = uri.partition("?")[2]
        headers = "Host: local-ojs.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html"
        data.append({
            "method": "GET",
            "uri": uri, "query_string": query_string, "body": "", "headers": headers, "label": 0
        })

    # 2. MALICIOUS TRAFFIC
    attacks = [
        # SQL Injection
        ("/index.php/testjournal/search?query=science' OR '1'='1", "SQLi", "GET", "Host: local-ojs.com\r\nUser-Agent: Nikto/2.1.6"),
        ("/index.php/testjournal/article/view/123", "SQLi", "POST", "User-Agent: curl/7.68.0"), # Missing Host
        ("/index.php/testjournal/search?query=admin'; DROP TABLE users--", "SQLi", "GET", "Host: local-ojs.com"), # Missing logic
        # XSS
        ("/index.php/testjournal/search?query=<script>alert('xss')</script>", "XSS", "GET", "Host: local-ojs.com\r\nUser-Agent: Mozilla/5.0"),
        ("/index.php/testjournal/user/register?username=\"><svg/onload=alert(1)>", "XSS", "GET", "Host: local-ojs.com"),
        # Path Traversal
        ("/index.php/testjournal/article/download/123/../../../../../etc/passwd", "PathTraverse", "GET", "Host: local-ojs.com"),
        ("/index.php/testjournal/search?query=../../../windows/win.ini", "PathTraverse", "TRACE", "Host: local-ojs.com\r\nUser-Agent: test"),
        # Command Injection
        ("/index.php/testjournal/search?query=science; ping -c 4 127.0.0.1", "CmdInj", "GET", "Host: local-ojs.com\r\nUser-Agent: bot"),
        ("/index.php/testjournal/search?query=`whoami`", "CmdInj", "POST", "Host: local-ojs.com\r\nUser-Agent: curl"),
    ]
    
    for _ in range(1500):
        attack = np.random.choice(len(attacks))
        uri, _, method, headers = attacks[attack]
        query_string = uri.partition("?")[2] if "?" in uri else ""
        data.append({
            "method": method,
            "uri": uri, "query_string": query_string, "body": "", "headers": headers, "label": 1
        })
        
    df = pd.DataFrame(data)
    print(f"[*] Dataset generated: {len(df)} records. (Normal: {len(df[df['label']==0])}, Attack: {len(df[df['label']==1])})")
    return df

def main():
    print("============================================")
    print("  WAF ML Model Trainer for OJS (Local) ")
    print("============================================")
    # 1. Generate Data
    df = generate_synthetic_dataset()
    
    # 2. Extract Features
    print("[*] Extracting 25 numerical features...")
    feature_list = []
    for _, row in df.iterrows():
        feats = extract_features(
            method=row.get('method', 'GET'),
            uri=row['uri'],
            query_string=row.get('query_string', ''),
            body=row['body'],
            headers=row['headers'],
            stateful_req_rate=np.random.randint(1, 100) if row['label'] == 1 else np.random.randint(1, 10)
        )
        feature_list.append(feats)
        
    X = np.array(feature_list)
    y = df['label'].values
    
    # 3. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 4. Train Model
    print("[*] Training Random Forest model...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)
    
    # 5. Evaluate
    y_pred = clf.predict(X_test)
    print("\n--- Model Evaluation ---")
    print(f"Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
    print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))
    
    # 6. Save Model
    os.makedirs(os.path.dirname(os.path.abspath(__file__)), exist_ok=True)
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "waf_model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(clf, f)
    print(f"[*] Model saved successfully to {model_path}")

if __name__ == "__main__":
    main()
