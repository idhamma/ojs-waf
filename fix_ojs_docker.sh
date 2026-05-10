#!/usr/bin/env bash
# fix_ojs_docker.sh
# Script untuk menerapkan semua fix ke folder ojs-docker (perlu sudo)
#
# Masalah yang diperbaiki:
#   1. nginx.conf: duplikat location blocks → nginx crash (exit status 1)
#   2. Dockerfile: nginx-extras → OpenResty (Lua support native)
#   3. supervisord.conf: nginx binary → openresty binary
#   4. docker-compose.yml: path Lua mount salah + tambah WAF_AGENT env vars
#
# Penggunaan:
#   bash fix_ojs_docker.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIGS_DIR="$SCRIPT_DIR/integrations/docker/ojs-docker-fixed-configs"
TARGET_DIR="$SCRIPT_DIR/integrations/docker/ojs-docker"

echo "=================================================="
echo "  OJS Docker WAF Fix Script"
echo "=================================================="
echo ""
echo "[*] Source configs: $CONFIGS_DIR"
echo "[*] Target dir    : $TARGET_DIR"
echo ""

# Cek apakah running sebagai root atau dengan sudo
if [ "$EUID" -ne 0 ]; then
    echo "[!] Script ini perlu dijalankan dengan sudo:"
    echo "    sudo bash fix_ojs_docker.sh"
    exit 1
fi

echo "[1/4] Menerapkan nginx.conf (OpenResty compatible)..."
cp "$CONFIGS_DIR/nginx.conf" "$TARGET_DIR/nginx.conf"
echo "      ✓ nginx.conf"

echo "[2/4] Menerapkan Dockerfile (nginx-extras → OpenResty)..."
cp "$CONFIGS_DIR/Dockerfile" "$TARGET_DIR/Dockerfile"
echo "      ✓ Dockerfile"

echo "[3/4] Menerapkan supervisord.conf (nginx → openresty binary)..."
cp "$CONFIGS_DIR/supervisord.conf" "$TARGET_DIR/supervisord.conf"
echo "      ✓ supervisord.conf"

echo "[4/4] Menerapkan docker-compose.yml (fix Lua mount + WAF env)..."
cp "$CONFIGS_DIR/docker-compose.yml" "$TARGET_DIR/docker-compose.yml"
echo "      ✓ docker-compose.yml"

echo ""
echo "[✓] Semua file berhasil diterapkan!"
echo ""
echo "=================================================="
echo "  Langkah selanjutnya:"
echo "=================================================="
echo ""
echo "1. Pastikan sidecar berjalan di host (port 9999):"
echo "   cd /home/insomniac/skripsi/support\ file"
echo "   python core/sidecar_agent.py --monitor"
echo ""
echo "2. Rebuild dan restart container OJS:"
echo "   cd integrations/docker/ojs-docker"
echo "   sudo docker compose down"
echo "   sudo docker compose build --no-cache"
echo "   sudo docker compose up -d"
echo ""
echo "3. Cek log untuk memastikan tidak ada error:"
echo "   sudo docker logs -f ojs-docker-ojs-app-1"
echo ""
echo "4. Test akses OJS di: http://localhost:8080"
echo ""
