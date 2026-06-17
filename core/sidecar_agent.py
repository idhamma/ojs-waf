"""
Sidecar WAF Agent — ML Inspection Engine (Userspace).

Menerima REQUEST_CHECK dari Nginx/Lua melalui TCP socket,
menjalankan ML inference (Random Forest), dan membalas WAF_DECISION.
Data request dicatat ke CSV untuk keperluan audit dan retraining model.

Arsitektur (Bare Metal / Non-Docker):
    Client → OpenResty (port 80) → waf_checker.lua
                  │ TCP :9999 (JSON)
                  ▼
             sidecar_agent.py (host)
                  │
                  ▼
             Apache (port 8080) → OJS (/var/www/ojs)

Mode:
    --monitor  : Log semua request ke CSV, selalu PASS — tidak perlu model ML.
                 Gunakan ini untuk FASE 1 (pengumpulan dataset).
    (default)  : Enforce — BLOCK request anomali berdasarkan model ML.
                 Membutuhkan waf_model.pkl yang sudah dilatih.

Blocking = DROP: sidecar mengembalikan decision BLOCK, Nginx langsung
memutus koneksi tanpa mengirim response (ngx.exit 444). Tidak ada
ban IP — setiap request dievaluasi secara independen.
"""

import argparse
import hashlib
import os
import sys
import signal
import json
import csv
import pickle
import queue
import re
import socket
import threading
import numpy as np
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)

# Import shared feature extractor
try:
    from ml_training.features import (
        FEATURE_NAMES,
        NUM_FEATURES,
        extract_features,
        selected_feature_indices,
    )
except ImportError as e:
    print(f"[!] Error importing ML methods: {e}")
    print("[!] Pastikan ml_training/features.py ada.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration defaults (overridable via CLI / model bundle)
# ---------------------------------------------------------------------------
DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_LISTEN_PORT = 9999
MODEL_VERSION = "rf-realistic-v1"
DATASET_BASE_DIR = os.path.join(PROJECT_DIR, "dataset")

# Default block threshold — overridden at load time by the model bundle's
# `block_threshold` value when present (set by ml_training.train_pipeline
# from the F1-optimal threshold sweep).
BLOCK_THRESHOLD = 0.50

# Headers to mask for privacy in dataset
SENSITIVE_HEADERS = {"cookie", "authorization", "x-csrf-token", "x-api-key"}
SENSITIVE_BODY_KEYS = {"password", "passwd", "token", "secret", "credit_card"}


# ---------------------------------------------------------------------------
# Privacy helpers
# ---------------------------------------------------------------------------

def _hash_cookie(cookie_value: str) -> str:
    """Return SHA-256 hash of cookie value for correlation without exposing data."""
    if not cookie_value or cookie_value == "[MASKED]":
        return ""
    return hashlib.sha256(cookie_value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _extract_auth_type(authorization_value: str) -> str:
    """Extract only the authorization scheme (e.g. 'Bearer', 'Basic'), strip token."""
    if not authorization_value or authorization_value == "[MASKED]":
        return ""
    parts = authorization_value.strip().split(None, 1)
    return parts[0] if parts else ""


def _mask_sensitive_body(body: str) -> str:
    """Mask sensitive values in request body (password, token, etc.)."""
    if not body:
        return body
    masked = body
    for key in SENSITIVE_BODY_KEYS:
        masked = re.sub(
            rf'("{key}"\s*:\s*")[^"]*(")',
            rf'\1[MASKED]\2',
            masked,
            flags=re.IGNORECASE,
        )
        masked = re.sub(
            rf'({key}=)[^&\s]*',
            rf'\1[MASKED]',
            masked,
            flags=re.IGNORECASE,
        )
    return masked


# ---------------------------------------------------------------------------
# Dataset Writer (queue-backed CSV append, daily rotation)
# ---------------------------------------------------------------------------

def _flatten_headers_subset(headers_subset_dict):
    """Flatten subset headers dict into stable CSV columns."""
    def _get(*keys):
        for k in keys:
            if k in headers_subset_dict:
                return headers_subset_dict.get(k) or ""
        return ""

    return {
        "host": _get("host", "Host"),
        "user_agent": _get("user-agent", "User-Agent"),
        "content_type": _get("content-type", "Content-Type"),
        "accept": _get("accept", "Accept"),
        "referer": _get("referer", "Referer"),
    }


class DatasetWriter:
    """Write dataset records to CSV (raw + labeled) using a background queue.

    - raw/   : setiap request yang masuk (tanpa label ML)
    - labeled/: setiap request + keputusan ML (decision, threat_score, attack_type)

    File dirotasi per hari (YYYY-MM-DD.csv).
    """

    RAW_FIELDS = [
        "request_id",
        "timestamp",
        "method",
        "uri",
        "query_string",
        "query_params_json",
        "host",
        "user_agent",
        "content_type",
        "accept",
        "referer",
        "cookie_hash",
        "authorization_type",
        "x_forwarded_for",
        "body_truncated",
        "body_len_original",
        "source_ip",
        "source_port",
        "server_ip",
        "server_port",
        "proto",
        "pcap_file",
        "tcp_flags",
        "tcp_flags_str",
        "response_status",
        "response_headers_json",
        "response_size",
        "response_time_ms",
        "response_body_truncated",
        "response_body_len_original",
        "headers_raw",
    ]

    LABELED_EXTRA_FIELDS = [
        "decision",
        "threat_score",
        "confidence",
        "attack_type",
        "model_version",
    ]

    def __init__(self, base_dir):
        self.base_dir = base_dir
        self._queue = queue.Queue()
        self._ensure_dirs()
        self._thread = threading.Thread(target=self._writer_loop, daemon=True)
        self._thread.start()

    def _ensure_dirs(self):
        for sub in ("raw", "labeled"):
            os.makedirs(os.path.join(self.base_dir, sub), exist_ok=True)

    def write_raw(self, record):
        self._queue.put(("raw", record))

    def write_labeled(self, record):
        self._queue.put(("labeled", record))

    def _csv_path(self, category, date_str):
        return os.path.join(self.base_dir, category, f"{date_str}.csv")

    def _writer_loop(self):
        while True:
            try:
                category, record = self._queue.get()
                date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                filepath = self._csv_path(category, date_str)

                if category == "raw":
                    fieldnames = self.RAW_FIELDS
                else:
                    fieldnames = self.RAW_FIELDS + self.LABELED_EXTRA_FIELDS

                file_exists = os.path.exists(filepath)
                with open(filepath, "a", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                    if not file_exists:
                        writer.writeheader()
                    writer.writerow(record)
            except Exception as e:
                print(f"[!] Dataset write error: {e}")


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------

def mask_headers(headers):
    """Return a copy of headers with sensitive values masked."""
    masked = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            masked[k] = "[MASKED]"
        else:
            masked[k] = v
    return masked


def headers_subset(headers):
    """Extract only dataset-relevant headers."""
    keys = {"host", "user-agent", "content-type", "accept", "referer"}
    return {k: v for k, v in headers.items() if k.lower() in keys}


def headers_to_str(headers):
    """Convert header dict to string for feature extraction compatibility."""
    return "\r\n".join(f"{k}: {v}" for k, v in headers.items())


# ---------------------------------------------------------------------------
# Main Sidecar Class
# ---------------------------------------------------------------------------

class SidecarWAF:
    def __init__(self, host, port, monitor_mode=False):
        self.host = host
        self.port = port
        self.monitor_mode = monitor_mode
        self.model = None
        # Column indices projecting the full 33-dim feature vector down to the
        # subset the loaded model was trained on. Defaults to identity (all 33)
        # and is narrowed in load_model() from the bundle's feature_names.
        self.feature_indices = list(range(NUM_FEATURES))
        self.dataset = DatasetWriter(DATASET_BASE_DIR)
        self._request_count = 0
        self._block_count = 0
        self.ip_timestamps = {}
        self.load_model()
        self.setup_socket()

    def load_model(self):
        global BLOCK_THRESHOLD
        model_path = os.path.join(PROJECT_DIR, "ml_training", "waf_model.pkl")
        if not os.path.exists(model_path):
            if self.monitor_mode:
                print(f"[!] Model tidak ditemukan: {model_path}")
                print("[!] Monitor/record mode: berjalan TANPA model ML.")
                print("[!] Semua traffic akan dicatat ke CSV (Phase 1 — dataset collection).")
                self.model = None
                return
            print(f"[!] Model tidak ditemukan: {model_path}")
            print("[!] Jalankan dulu: python -m ml_training.train_pipeline")
            sys.exit(1)

        print(f"[*] Loading ML model: {model_path}")
        with open(model_path, "rb") as f:
            payload = pickle.load(f)

        # Support both new bundle dicts and legacy raw classifier pickles.
        if isinstance(payload, dict) and "model" in payload:
            self.model = payload["model"]
            bundle_names = payload.get("feature_names")
            if bundle_names is not None:
                # The bundle may train on a subset of the 33-dim vector (e.g. the
                # real-data model uses 22 features). Verify every bundle feature
                # is one the sidecar can produce, then store the projection so
                # predict() feeds the model exactly the columns it was trained on.
                try:
                    self.feature_indices = selected_feature_indices(list(bundle_names))
                except KeyError as exc:
                    print("[!] Feature mismatch between sidecar and model bundle.")
                    print(f"    sidecar can produce: {list(FEATURE_NAMES)[:6]}... "
                          f"({NUM_FEATURES} dims)")
                    print(f"    bundle requires    : {list(bundle_names)[:6]}... "
                          f"({len(bundle_names)} dims)")
                    print(f"    unknown feature(s) : {exc}")
                    sys.exit(1)
                print(f"[*] Model uses {len(self.feature_indices)}/{NUM_FEATURES} "
                      f"features (projected from the shared extractor).")
            bundle_threshold = payload.get("block_threshold")
            if isinstance(bundle_threshold, (int, float)):
                BLOCK_THRESHOLD = float(bundle_threshold)
                print(f"[*] Block threshold loaded from bundle: {BLOCK_THRESHOLD:.2f}")
            bundle_version = payload.get("model_version")
            if bundle_version:
                print(f"[*] Bundle version: {bundle_version}")
            trained_at = payload.get("trained_at")
            if trained_at:
                print(f"[*] Trained at   : {trained_at}")
        else:
            self.model = payload
            print("[!] Legacy model artifact detected — no feature_names verification.")

        n_est = getattr(self.model, "n_estimators", "?")
        max_d = getattr(self.model, "max_depth", "?")
        print(f"[✓] Model loaded — {type(self.model).__name__} "
              f"({n_est} trees, max_depth={max_d})")

    def setup_socket(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(64)
        print(f"[*] Listening on TCP {self.host}:{self.port}")

    # ---- ML Inference ----

    def predict(self, method, uri, query_string, body, headers_str, source_ip):
        """Run ML inference and return (prediction, probability, attack_type)."""
        if self.model is None:
            # No model loaded — monitor/record mode (Phase 1). Always PASS.
            return 0, 0.0, "NONE"

        now = datetime.now(timezone.utc).timestamp()
        
        # Cleanup old timestamps (keep last 60 seconds rolling window)
        recent_reqs = [t for t in self.ip_timestamps.get(source_ip, []) if now - t < 60]
        recent_reqs.append(now)
        self.ip_timestamps[source_ip] = recent_reqs
        stateful_req_rate = float(len(recent_reqs))

        features = extract_features(
            method=method,
            uri=uri,
            query_string=query_string,
            body=body,
            headers=headers_str,
            stateful_req_rate=stateful_req_rate
        )
        # Project the full 33-dim vector down to the model's trained subset.
        X = np.array([[features[i] for i in self.feature_indices]])

        prediction = self.model.predict(X)[0]           # 0=Normal, 1=Attack
        probabilities = self.model.predict_proba(X)[0]   # [p_normal, p_attack]
        threat_score = float(probabilities[1])

        attack_type = "NONE"
        if prediction == 1:
            attack_type = self._classify_attack(uri, body)

        return prediction, threat_score, attack_type

    def _classify_attack(self, uri, body):
        """Heuristic regex to classify attack type for response payload only.

        The output of this function MUST NOT be used as a ground-truth label
        for retraining — it is a coarse post-hoc tag used when the ML model
        has already decided BLOCK. URL-decoding is applied so encoded
        attacks reach the same patterns as their plaintext form.
        """
        raw = (uri or "") + " " + (body or "")
        try:
            decoded_once = unquote(raw)
            decoded = unquote(decoded_once)
        except Exception:
            decoded = raw
        text = decoded.lower()

        # RCE in this OJS deployment is abuse of the native import/export plugin
        # route (the only RCE family present in the captured dataset). Checked
        # first so genuine import-route attacks are tagged RCE, not UNKNOWN.
        if re.search(
            r"(nativeimportexportplugin|management/importexport|/importexport/plugin)",
            text,
        ):
            return "RCE"
        if re.search(
            r"(union(\s+all)?\s+select|select\s+.*\s+from"
            r"|or\s*['\"`]?\s*1\s*['\"`]?\s*=\s*['\"`]?\s*1"
            r"|and\s*['\"`]?\s*1\s*['\"`]?\s*=\s*['\"`]?\s*1"
            r"|or\s+1\s*=\s*1|drop\s+table|sleep\s*\(|waitfor\s+delay"
            r"|benchmark\s*\(|extractvalue\s*\(|updatexml\s*\(|load_file\s*\()",
            text,
        ):
            return "SQL_INJECTION"
        if re.search(
            r"(<\s*script|<\s*svg|<\s*iframe|<\s*img[^>]*on\w+\s*="
            r"|javascript\s*:|vbscript\s*:|data\s*:\s*text/html"
            r"|on(error|load|click|focus|mouseover|toggle)\s*="
            r"|alert\s*\(|prompt\s*\(|eval\s*\(|srcdoc\s*=)",
            text,
        ):
            return "XSS"
        if re.search(
            r"(\.\./|\.\.\\|\.{4,}/|/etc/passwd|/etc/shadow|/proc/self"
            r"|c:\\windows|win\.ini|boot\.ini)",
            text,
        ):
            return "PATH_TRAVERSAL"
        if re.search(
            r"(`[^`]*`|\$\([^)]*\)|\$\{ifs[^}]*\}|\$ifs\$"
            r"|(?:[|&;]{1,2}|\s)\s*(?:cat|ls|whoami|id|uname|nc|bash|sh|curl|wget|python|perl|ruby)\b"
            r"|/bin/sh|/bin/bash|nc\s+-[el])",
            text,
        ):
            return "COMMAND_INJECTION"
        return "UNKNOWN_ATTACK"

    # ---- Health Check Handler ----

    def _handle_health(self, conn):
        """Reply to a HEALTH_CHECK probe with sidecar status."""
        reply = {
            "type": "HEALTH_RESPONSE",
            "status": "ok",
            "model_version": MODEL_VERSION,
            "total_requests": self._request_count,
            "total_blocked": self._block_count,
            "monitor_mode": self.monitor_mode,
        }
        try:
            conn.sendall((json.dumps(reply) + "\n").encode("utf-8"))
        except Exception as e:
            print(f"[!] Health reply error: {e}")

    # ---- Request Handler ----

    def handle_request(self, msg, conn):
        """Process a REQUEST_CHECK message and reply WAF_DECISION."""
        self._request_count += 1

        request_id = msg.get("request_id", "unknown")
        uri = msg.get("uri", "")
        body = msg.get("body", "")
        headers = msg.get("headers", {})
        method = msg.get("method", "GET")
        source_ip = msg.get("source_ip", "0.0.0.0")
        source_port = msg.get("source_port", 0)
        server_ip = msg.get("server_ip", "0.0.0.0")
        server_port = msg.get("server_port", 0)
        timestamp = msg.get("timestamp", datetime.now(timezone.utc).isoformat())

        # --- Extract additional fields ---
        query_string = msg.get("query_string", "")
        if not query_string and "?" in uri:
            _, _, query_string = uri.partition("?")

        cookie_raw = msg.get("cookie", "")
        if not cookie_raw:
            cookie_raw = headers.get("cookie", headers.get("Cookie", ""))
        cookie_hash = _hash_cookie(cookie_raw)

        auth_raw = msg.get("authorization", "")
        if not auth_raw:
            auth_raw = headers.get("authorization", headers.get("Authorization", ""))
        authorization_type = _extract_auth_type(auth_raw)

        x_forwarded_for = msg.get("x_forwarded_for", "")
        if not x_forwarded_for:
            x_forwarded_for = headers.get("x-forwarded-for", headers.get("X-Forwarded-For", ""))

        # ── Fase 2: Data Sanitization & Masking ──
        masked_body = _mask_sensitive_body(body[:16384])
        masked_headers_dict = mask_headers(headers)

        # ── Async Logging: Write raw dataset record ──
        subset = headers_subset(masked_headers_dict)
        flat = _flatten_headers_subset(subset)
        raw_record = {
            "request_id": request_id,
            "timestamp": timestamp,
            "method": method,
            "uri": uri,
            "query_string": query_string,
            "query_params_json": "{}",
            **flat,
            "cookie_hash": cookie_hash,
            "authorization_type": authorization_type,
            "x_forwarded_for": x_forwarded_for,
            "body_truncated": masked_body,
            "body_len_original": len(body),
            "source_ip": source_ip,
            "source_port": source_port,
            "server_ip": server_ip,
            "server_port": server_port,
            "proto": "TCP",
            "pcap_file": "",
            "tcp_flags": "",
            "tcp_flags_str": "",
            "response_status": 0,
            "response_headers_json": "{}",
            "response_size": 0,
            "response_time_ms": -1,
            "response_body_truncated": "",
            "response_body_len_original": 0,
            "headers_raw": json.dumps(masked_headers_dict),
        }
        self.dataset.write_raw(raw_record)

        # ── Fase 3: Feature Extraction ──
        headers_str = headers_to_str(headers)

        # ── Fase 4: Model Inference & Classification ──
        prediction, threat_score, attack_type = self.predict(method, uri, query_string, body, headers_str, source_ip)

        # ── Fase 5: Decision — evaluate threshold ──
        if prediction == 1 and threat_score >= BLOCK_THRESHOLD:
            decision = "BLOCK"
        else:
            decision = "PASS"
            attack_type = "NONE"

        # Monitor mode override: always return PASS to Lua
        effective_decision = decision
        if self.monitor_mode and decision == "BLOCK":
            effective_decision = "PASS"

        if decision == "BLOCK":
            self._block_count += 1

        confidence = min(threat_score * 1.1, 1.0) if prediction == 1 else 1.0 - threat_score

        # ── Build WAF_DECISION response ──
        waf_decision = {
            "type": "WAF_DECISION",
            "request_id": request_id,
            "decision": effective_decision,
            "threat_score": round(threat_score, 4),
            "confidence": round(confidence, 4),
            "attack_type": attack_type,
            "model_version": MODEL_VERSION,
        }

        # Send reply to Lua via TCP
        try:
            reply = json.dumps(waf_decision) + "\n"
            conn.sendall(reply.encode("utf-8"))
        except Exception as e:
            print(f"[!] Reply send error: {e}")

        # ── Async Logging: Write labeled dataset record ──
        # NOTE: we persist the model's decision (not a downstream regex) so
        # retraining on this log measures the ML signal itself rather than
        # reinforcing a fixed rule catalog. The rule classifier is only used
        # to populate the human-readable attack_type tag *when the model has
        # already chosen BLOCK*.
        labeled_record = {
            **raw_record,
            "decision": decision,
            "threat_score": round(threat_score, 4),
            "confidence": round(confidence, 4),
            "attack_type": attack_type,
            "model_version": MODEL_VERSION,
        }
        self.dataset.write_labeled(labeled_record)

        # ── Console Log ──
        if decision == "BLOCK":
            mode_tag = " [MONITOR→PASS]" if self.monitor_mode else " [DROP]"
            print(f"🔴 [{decision}]{mode_tag} {method} {uri[:80]} "
                  f"(score={threat_score:.3f}, type={attack_type}, "
                  f"ip={source_ip}, id={request_id[:12]})")
        else:
            print(f"🟢 [PASS] {method} {uri[:80]} "
                  f"(score={threat_score:.3f}, ip={source_ip})")

    # ---- Connection Handler ----

    def _handle_connection(self, conn, addr):
        """Handle a single Lua connection (one JSONL message per connection)."""
        try:
            buf = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line.decode("utf-8"))
                    except json.JSONDecodeError as e:
                        print(f"[!] JSON parse error: {e}")
                        continue

                    msg_type = msg.get("type", "")
                    if msg_type == "REQUEST_CHECK":
                        self.handle_request(msg, conn)
                    elif msg_type == "HEALTH_CHECK":
                        self._handle_health(conn)
                    else:
                        print(f"[!] Unknown message type: {msg_type}")
        except ConnectionResetError:
            pass
        except Exception as e:
            print(f"[!] Connection error: {e}")
        finally:
            conn.close()

    # ---- Main Loop ----

    def run(self):
        mode_str = "MONITOR (log only, no blocking)" if self.monitor_mode else "ENFORCE (PASS/BLOCK)"
        print(f"[*] Mode         : {mode_str}")
        print(f"[*] Threshold    : {BLOCK_THRESHOLD}")
        print(f"[*] Dataset dir  : {DATASET_BASE_DIR}")
        print(f"[*] Model version: {MODEL_VERSION}")
        print("[*] Waiting for connections from Nginx/Lua...")
        print()

        while True:
            try:
                conn, addr = self.server.accept()
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr),
                    daemon=True,
                )
                t.start()
            except KeyboardInterrupt:
                print(f"\n[*] Shutting down... "
                      f"(total={self._request_count}, blocked={self._block_count})")
                break
            except Exception as e:
                print(f"[!] Accept error: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ML-Based WAF Sidecar Agent (Userspace)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Contoh penggunaan:
  # Mode enforce (default) — BLOCK request anomali
  python sidecar_agent.py

  # Mode monitor — log saja, semua traffic diloloskan
  python sidecar_agent.py --monitor

  # Custom port
  python sidecar_agent.py --port 8888 --monitor
""",
    )
    parser.add_argument(
        "--monitor", action="store_true",
        help="Monitor mode: log keputusan ML tapi selalu PASS (untuk dataset collection)",
    )
    parser.add_argument(
        "--host", default=DEFAULT_LISTEN_HOST,
        help=f"Listen host (default: {DEFAULT_LISTEN_HOST})",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_LISTEN_PORT,
        help=f"Listen port (default: {DEFAULT_LISTEN_PORT})",
    )

    args = parser.parse_args()

    print("=" * 56)
    print("  ML-Based WAF Sidecar Agent (Userspace)  v2.0")
    print("=" * 56)

    waf = SidecarWAF(
        host=args.host,
        port=args.port,
        monitor_mode=args.monitor,
    )

    # Graceful shutdown on SIGTERM
    def handle_sigterm(signum, frame):
        print(f"\n[*] SIGTERM received, shutting down... "
              f"(total={waf._request_count}, blocked={waf._block_count})")
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_sigterm)

    waf.run()


if __name__ == "__main__":
    main()
