import os
import numpy as np
import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

from ml_training.features import extract_features, calculate_entropy  # noqa: F401  (re-exported for backwards compat)

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
