#!/usr/bin/env bash
# fix_ojs_docker.sh
# Apply runtime/source fixes for the local OJS + OpenResty WAF Docker setup.
#
# Fixes:
#   1. OpenResty workers run as www-data so they can access PHP-FPM socket.
#   2. WAF env vars are declared in nginx.conf.
#   3. Docker compose uses the current Docker gateway IP for the host sidecar.
#   4. Lua WAF checker avoids duplicate checks after internal redirects.
#   5. OJS writable volumes are owned by www-data.
#
# Usage:
#   sudo bash fix_ojs_docker.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$SCRIPT_DIR/integrations/docker/ojs-docker"
NGINX_CONF="$TARGET_DIR/nginx.conf"
COMPOSE_FILE="$TARGET_DIR/docker-compose.yml"
WAF_LUA="$TARGET_DIR/waf_checker.lua"

echo "=================================================="
echo "  OJS Docker WAF Repair Script"
echo "=================================================="
echo "[*] Target dir: $TARGET_DIR"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "[!] This script must run with sudo:"
    echo "    sudo bash fix_ojs_docker.sh"
    exit 1
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "[!] Target directory not found: $TARGET_DIR"
    exit 1
fi

echo "[1/5] Fixing OpenResty worker user and env declarations..."
if ! grep -q '^user www-data;' "$NGINX_CONF"; then
    sed -i '1iuser www-data;\nenv WAF_AGENT_HOST;\nenv WAF_AGENT_PORT;\n' "$NGINX_CONF"
fi

if ! grep -q 'resolver 127.0.0.11' "$NGINX_CONF"; then
    sed -i '/^http {/a\    resolver 127.0.0.11 ipv6=off valid=30s;' "$NGINX_CONF"
fi

echo "[2/5] Setting sidecar host to current Docker gateway IP..."
GATEWAY_IP="$(docker network inspect ojs-docker_default \
    --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)"

if [ -z "$GATEWAY_IP" ]; then
    GATEWAY_IP="172.19.0.1"
fi

sed -i "s/WAF_AGENT_HOST=.*/WAF_AGENT_HOST=$GATEWAY_IP/" "$COMPOSE_FILE"
echo "      WAF_AGENT_HOST=$GATEWAY_IP"

echo "[3/5] Adding duplicate-check guard to waf_checker.lua..."
if ! grep -q 'ngx.ctx.waf_checked' "$WAF_LUA"; then
    sed -i '/local function check_request()/a\
    if ngx.ctx.waf_checked then\
        return\
    end\
    ngx.ctx.waf_checked = true\
' "$WAF_LUA"
fi

echo "[4/5] Fixing mounted OJS writable directory ownership..."
mkdir -p "$TARGET_DIR/ojs_files" "$TARGET_DIR/public"
chown -R 33:33 "$TARGET_DIR/ojs_files" "$TARGET_DIR/public"
chmod -R u+rwX,g+rwX "$TARGET_DIR/ojs_files" "$TARGET_DIR/public"

echo "[5/5] Validating running container when available..."
if docker ps --format '{{.Names}}' | grep -q '^ojs-docker-ojs-app-1$'; then
    docker exec ojs-docker-ojs-app-1 sh -lc \
        'chown -R www-data:www-data /var/www/ojs_files /var/www/ojs/public &&
         chmod -R u+rwX,g+rwX /var/www/ojs_files /var/www/ojs/public &&
         /usr/local/openresty/bin/openresty -t &&
         /usr/local/openresty/bin/openresty -s reload'
    echo "      Running container repaired and OpenResty reloaded."
else
    echo "      Container is not running; source files were repaired."
fi

echo ""
echo "[✓] Repair complete."
echo ""
echo "Recommended start sequence:"
echo "  1. Start sidecar on the host:"
echo "     cd '$SCRIPT_DIR'"
echo "     venv310/bin/python -u core/sidecar_agent.py --monitor"
echo ""
echo "  2. Restart OJS if needed:"
echo "     cd '$TARGET_DIR'"
echo "     docker compose up -d --build"
echo ""
