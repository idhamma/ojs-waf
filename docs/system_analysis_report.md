# System Analysis Report

## Runtime Verification

Environment used:

```text
venv310/bin/python
Python 3.10.14
numpy 1.24.3
scikit-learn 1.7.2
pandas 2.3.3
```

The sidecar starts successfully with:

```bash
venv310/bin/python -u core/sidecar_agent.py --monitor
```

Verified behavior:

- `ml_training/waf_model.pkl` loads correctly.
- Sidecar listens on TCP `0.0.0.0:9999`.
- Monitor mode starts correctly.
- A normal OJS-style request returns `PASS`.
- A SQL-injection-style request is internally detected as `BLOCK`, but monitor
  mode returns `PASS` as designed.
- With the sidecar running, OpenResty successfully sends live OJS browser
  requests to the sidecar over TCP.

## Current Architecture

Active request path:

```text
Browser
  -> OpenResty container on localhost:8080
  -> integrations/docker/ojs-docker/waf_checker.lua
  -> Python sidecar on host TCP :9999
  -> Random Forest model
  -> WAF_DECISION
  -> PHP-FPM / OJS
  -> MariaDB
```

Core active files:

```text
core/sidecar_agent.py
ml_training/train_waf_model.py
ml_training/waf_model.pkl
integrations/waf_checker.lua
integrations/docker/ojs-docker/waf_checker.lua
integrations/docker/ojs-docker/nginx.conf
integrations/docker/ojs-docker/docker-compose.yml
```

The active model feature extractor is `extract_features()` in
`ml_training/train_waf_model.py`. The sidecar does not use the old
`core/waf_ml_features.py` extractor.

## Workflow

1. OpenResty receives the HTTP request.
2. Lua WAF code collects method, URI, query string, headers, body, source IP,
   ports, cookie, authorization type, and X-Forwarded-For.
3. Lua sends a JSON Lines `REQUEST_CHECK` message to the Python sidecar.
4. The sidecar writes a raw CSV dataset row.
5. The sidecar extracts 25 numerical features.
6. Random Forest predicts normal or attack.
7. If attack probability is at least `0.70`, the real decision is `BLOCK`.
8. In monitor mode, the real decision is logged but Lua receives `PASS`.
9. Lua either passes the request to OJS/PHP-FPM or closes it with Nginx `444`.
10. The sidecar writes a labeled CSV dataset row for retraining and audit.

## Docker / OJS 502 Root Cause

Observed browser response before fix:

```text
HTTP/1.1 502 Bad Gateway
Server: openresty/1.29.2.3
```

Confirmed error from OpenResty log:

```text
connect() to unix:/run/php/php8.1-fpm.sock failed (13: Permission denied)
```

PHP-FPM was running and the socket existed:

```text
/run/php/php8.1-fpm.sock owned by www-data:www-data mode 660
```

Root cause:

OpenResty worker processes were not configured to run as `www-data`, so they
could not open the PHP-FPM Unix socket.

Live-container fix applied:

```text
Added `user www-data;` to the running container's OpenResty nginx.conf.
Reloaded OpenResty.
```

Result:

```text
http://localhost:8080/ changed from 502 to 302 Found
```

After following the redirect, OJS returned `500` because `/var/www/ojs_files`
was mounted as `root:root` and PHP could not write usage/scheduled-task logs.

Confirmed log:

```text
fopen(/var/www/ojs_files/...): Failed to open stream: Permission denied
flock(): Argument #1 ($stream) must be of type resource, bool given
```

Live-container fix applied:

```bash
chown -R www-data:www-data /var/www/ojs_files /var/www/ojs/public
chmod -R u+rwX,g+rwX /var/www/ojs_files /var/www/ojs/public
```

Result after both fixes:

```text
curl -I -L http://localhost:8080/
HTTP/1.1 302 Found
HTTP/1.1 200 OK
```

## Permanent Docker Fix Needed

The host Docker files under `integrations/docker/ojs-docker/` are owned by
`root:root`, so I could not edit them directly without sudo. The running
container is fixed, but rebuilding the image can lose part of the fix unless the
source config is updated.

Apply these permanent changes to `integrations/docker/ojs-docker/nginx.conf`:

```nginx
user www-data;
env WAF_AGENT_HOST;
env WAF_AGENT_PORT;

events {
    worker_connections 1024;
}
```

Also add a Docker DNS resolver inside the `http` block if you keep
`WAF_AGENT_HOST=host.docker.internal`:

```nginx
resolver 127.0.0.11 ipv6=off valid=30s;
```

Without the resolver, Lua cosocket reports:

```text
no resolver defined to resolve "host.docker.internal"
```

Alternatively, set the sidecar host to the Docker gateway IP, such as:

```yaml
WAF_AGENT_HOST=172.19.0.1
```

The Docker volume ownership should also be made persistent. Add startup logic in
the container entrypoint/supervisor path or Dockerfile to run:

```bash
chown -R www-data:www-data /var/www/ojs_files /var/www/ojs/public
chmod -R u+rwX,g+rwX /var/www/ojs_files /var/www/ojs/public
```

I also updated `fix_ojs_docker.sh` so it applies these fixes idempotently when
run with sudo.

## Improvement Points

1. Add a dedicated sidecar health check.
   The WAF currently fails open, which is good for availability, but there is no
   clear health endpoint or container dependency check.

2. Avoid repeated WAF checks on one request.
   Current Nginx routing can run Lua once in `/` and again after internal
   redirect to `/index.php`. Add a Lua guard such as `ngx.ctx.waf_checked`.

3. Keep OpenResty environment handling explicit.
   Nginx does not expose arbitrary environment variables unless declared with
   `env` in the main config context.

4. Improve model labeling.
   SQLi test traffic was model-detected as attack, but the regex label returned
   `UNKNOWN_ATTACK` for one common payload. The `_classify_attack()` regex should
   cover simpler `OR '1'='1` variants.

5. Split training code from runtime feature code.
   The sidecar imports runtime features from `ml_training/train_waf_model.py`.
   A cleaner structure would move shared feature extraction into a stable module,
   then import that from both training and runtime.

6. Add dependency metadata.
   The repo has a working `venv310`, but no committed `requirements.txt` or
   lock file. Rebuilding the environment will be fragile.

7. Add tests for the TCP protocol.
   A small integration test should start the sidecar, send JSONL requests, and
   assert `PASS`/`BLOCK` behavior.

8. Align documentation and schema.
   Some docs/schema files describe older feature counts or response fields that
   the current sidecar does not write.

9. Do not commit runtime state.
   Python caches, logs, virtual environments, Docker DB volumes, and OJS runtime
   files should stay out of Git.

## Files Moved To `unused/`

Moved because they are generated, stale, broken demos, old datasets, or a
different eBPF/DDoS architecture:

```text
unused/root_cache/__pycache__/
unused/root_cache/scripts__pycache__/
unused/core/__pycache__/
unused/core/client_library.py
unused/core/waf_ml_features.py
unused/integrations/demo_app.py
unused/integrations/nginx_integration.py
unused/ml_training/__pycache__/
unused/ml_training/train_ddos_model.py
unused/ml_training/train_rf_ddos_model.py
unused/ml_training/dt_model_ebpf.json
unused/ml_training/rf_model_ebpf.json
unused/dataset/raw/old dataset eight may.csv
unused/dataset/labeled/old dataset eight may.csv
unused/dataset/test_runs/raw/2026-05-11.csv
unused/dataset/test_runs/labeled/2026-05-11.csv
unused/dataset/test_runs/raw/2026-05-11-waf-live.csv
unused/dataset/test_runs/labeled/2026-05-11-waf-live.csv
unused/dataset/meta/schema_v1.json
unused/dataset/meta/schema_v2.json
unused/runtime_logs/sidecar.log
```
