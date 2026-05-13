# ML-Based WAF System Explanation

## Purpose

This project is a userspace Web Application Firewall (WAF) prototype for
Open Journal Systems (OJS). The active runtime path inspects HTTP requests in
OpenResty/Nginx, sends request metadata to a Python sidecar service, runs a
Random Forest model, and returns a PASS or BLOCK decision.

The system does not ban IP addresses. Each request is evaluated independently,
with a small in-memory request-rate feature per source IP.

## Active Runtime Components

### 1. OpenResty / Nginx layer

Main files:

- `integrations/waf_checker.lua`
- `integrations/nginx_waf.conf`
- `integrations/docker-compose.yml`

`waf_checker.lua` runs during the Nginx access phase. For every request that is
not bypassed, it collects:

- request id
- method
- URI and query string
- headers
- request body, capped at 16 KB
- source and server address metadata
- cookie, authorization, and X-Forwarded-For values

It sends this data as one JSON object followed by a newline to the sidecar over
TCP. The default target is:

```text
host: 172.19.0.1 or host.docker.internal
port: 9999
protocol: JSON Lines over TCP
```

If the sidecar is unavailable, the Lua integration is fail-open and allows the
request to continue.

### 2. Python sidecar WAF

Main file:

- `core/sidecar_agent.py`

The sidecar listens on TCP `0.0.0.0:9999` by default. It expects messages with:

```json
{
  "type": "REQUEST_CHECK",
  "request_id": "...",
  "method": "GET",
  "uri": "/index.php/testjournal/search?query=science",
  "headers": {},
  "body": "",
  "source_ip": "127.0.0.1"
}
```

For each request, it:

1. extracts and normalizes request fields
2. hashes cookies and strips authorization token values
3. masks sensitive body keys such as password, token, and secret
4. writes a raw dataset record asynchronously
5. extracts model features
6. runs Random Forest inference
7. classifies attack type with simple regex heuristics when the model predicts attack
8. returns a `WAF_DECISION`
9. writes a labeled dataset record asynchronously

The default blocking threshold is `0.70`.

### 3. ML training and model artifact

Main active files:

- `ml_training/train_waf_model.py`
- `ml_training/waf_model.pkl`

`train_waf_model.py` creates a synthetic OJS-focused dataset, extracts 25
numeric request features, trains a `RandomForestClassifier`, evaluates it, and
saves the model to `ml_training/waf_model.pkl`.

The sidecar imports `extract_features` from this training file, so the feature
order in `train_waf_model.py` is the production feature contract for the active
WAF path.

Important feature groups:

- request and payload lengths
- entropy
- special character counts
- SQL, XSS, path traversal, and command-injection pattern counts
- OJS-specific URI context
- risky HTTP methods
- query-string anomalies
- missing or unusual headers
- body non-ASCII ratio
- per-source request rate over the last 60 seconds

### 4. Dataset logging

Main folders:

- `dataset/raw/`
- `dataset/labeled/`
- `dataset/meta/`

The sidecar writes daily CSV files:

- `dataset/raw/YYYY-MM-DD.csv`
- `dataset/labeled/YYYY-MM-DD.csv`

Raw records contain sanitized request data. Labeled records add:

- decision
- threat score
- confidence
- attack type
- model version

The currently implemented CSV shape in `sidecar_agent.py` is closest to the v3
schema, but it is not a full match. The sidecar currently writes request fields
only and does not write response fields, TCP flags, `query_params_json`, `proto`,
or `pcap_file`.

## Request Flow

```text
Client
  -> OpenResty / Nginx
  -> waf_checker.lua access phase
  -> TCP JSONL REQUEST_CHECK
  -> core/sidecar_agent.py
  -> ml_training/train_waf_model.extract_features()
  -> ml_training/waf_model.pkl Random Forest inference
  -> WAF_DECISION response
  -> waf_checker.lua enforcement
  -> OJS upstream if PASS
  -> connection close with Nginx 444 if BLOCK
```

Detailed flow:

1. A client sends an HTTP request to OpenResty.
2. `waf_checker.lua` skips health checks, favicon, robots.txt, and OPTIONS.
3. Lua builds a `REQUEST_CHECK` JSON object.
4. Lua sends the object to the Python sidecar at port `9999`.
5. The sidecar writes the request into the raw dataset queue.
6. The sidecar calculates 25 model features.
7. The Random Forest returns normal/attack prediction and probability.
8. If prediction is attack and `threat_score >= 0.70`, the real decision is
   `BLOCK`; otherwise it is `PASS`.
9. In monitor mode, the sidecar still records the real decision but returns
   `PASS` to Nginx.
10. Lua enforces the returned decision.
11. The sidecar writes a labeled dataset row for audit and retraining.

## Operating Modes

### Enforce mode

Command:

```bash
python core/sidecar_agent.py
```

Behavior:

- normal traffic returns `PASS`
- detected attacks return `BLOCK`
- Nginx closes blocked connections with status `444`

### Monitor mode

Command:

```bash
python core/sidecar_agent.py --monitor
```

Behavior:

- the sidecar still calculates the real model decision
- the labeled dataset stores the real decision
- the response sent to Lua is always `PASS`

This mode is useful for collecting traffic before enforcing blocking.

## Important Design Notes

- The active sidecar protocol is TCP JSON Lines, not Unix domain sockets.
- `core/blocking_mechanism.py` is a compatibility stub. Blocking is done by
  Nginx/Lua, not by eBPF or kernel-level logic.
- `core/waf_ml_features.py` is a separate 20-feature extractor demo and is not
  used by the active sidecar. The active extractor is in
  `ml_training/train_waf_model.py`.
- The DDoS/eBPF training files generate JSON artifacts for a different
  architecture and are not part of the current userspace OJS WAF request path.
- Some integration demo files are stale and import `others.client_library`,
  which does not exist in this repository.

## Main Gaps Found

1. `core/client_library.py` uses Unix sockets, but the active sidecar listens on
   TCP. It cannot communicate with the current sidecar without changes.
2. `integrations/demo_app.py` and `integrations/nginx_integration.py` import
   `others.client_library`, which is missing. They are currently broken demos.
3. `docs/architecture_plan.md` says the model uses 15 features, but the active
   `train_waf_model.py` and sidecar path use 25 features.
4. `integrations/nginx_waf.conf` comments mention Unix sockets and HTTP 403 in
   places, while the active Lua path uses TCP and `ngx.exit(444)`.
5. Dataset schema v3 is broader than the active writer implementation.
6. Generated runtime files, virtual environments, and Docker database volumes
   are present in the project tree and should stay out of source control.

