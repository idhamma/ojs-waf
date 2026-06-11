#!/usr/bin/env bash
# setup_baremetal.sh
# Pasang ML-Based WAF (OpenResty + Python sidecar) di atas OJS yang berjalan
# di Nginx port 80 pada server bare metal (tanpa Docker).
#
# Apa yang dilakukan script ini:
#   1. Install OpenResty (jika belum ada)
#   2. Install dependensi Python (requirements.txt)
#   3. Pindahkan Nginx OJS dari port 80 → 127.0.0.1:8080
#   4. Salin konfigurasi WAF (OpenResty akan listen di 0.0.0.0:80)
#   5. Salin waf_checker.lua ke /etc/openresty/
#   6. Start/reload OpenResty
#   7. Buat systemd service untuk sidecar_agent (mode --monitor)
#   8. Start sidecar_agent
#
# Fase operasi:
#   Phase 1 — Monitor/Record: sidecar hanya merekam traffic ke CSV, tidak block.
#             Jalankan: sudo systemctl start waf-sidecar
#   Phase 2 — Enforce: setelah model dilatih, edit /etc/default/waf-sidecar
#             dan hapus flag --monitor, lalu: sudo systemctl restart waf-sidecar
#
# Penggunaan:
#   sudo bash integrations/setup_baremetal.sh
#
# Target:
#   OJS di /var/www/ojs, http://10.34.100.110/

set -euo pipefail

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OJS_DIR="/var/www/ojs"
OJS_NGINX_PORT=8080          # Port tujuan setelah Nginx OJS dipindah
WAF_LISTEN_IP="0.0.0.0"
WAF_LISTEN_PORT=80
SIDECAR_PORT=9999
OPENRESTY_CONF_DIR="/etc/openresty"
OPENRESTY_SITES_DIR="/etc/openresty/conf.d"
SIDECAR_USER="$(logname 2>/dev/null || echo "$SUDO_USER")"
PYTHON_BIN="$(which python3 2>/dev/null || which python)"

echo "=========================================================="
echo "  ML-Based WAF — Bare Metal Setup"
echo "  OJS: $OJS_DIR  |  http://10.34.100.110/"
echo "=========================================================="
echo "[*] Project dir : $PROJECT_DIR"
echo "[*] Python      : $PYTHON_BIN"
echo "[*] Sidecar user: $SIDECAR_USER"
echo ""

# ---------------------------------------------------------------------------
# Guard: must run as root
# ---------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    echo "[!] Jalankan dengan sudo:"
    echo "    sudo bash integrations/setup_baremetal.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Install OpenResty
# ---------------------------------------------------------------------------
echo "[1/8] Memeriksa OpenResty..."
if ! command -v openresty &>/dev/null; then
    echo "      OpenResty tidak ditemukan, menginstall..."
    # Detect distro
    if [ -f /etc/debian_version ]; then
        # Ubuntu / Debian
        apt-get install -y gnupg lsb-release curl
        CODENAME="$(lsb_release -sc)"
        curl -fsSL https://openresty.org/package/pubkey.gpg \
            | gpg --dearmor -o /usr/share/keyrings/openresty.gpg
        echo "deb [signed-by=/usr/share/keyrings/openresty.gpg] http://openresty.org/package/ubuntu $CODENAME main" \
            > /etc/apt/sources.list.d/openresty.list
        apt-get update -q
        apt-get install -y openresty
    elif [ -f /etc/redhat-release ]; then
        # CentOS / RHEL / AlmaLinux
        yum install -y yum-utils
        yum-config-manager --add-repo https://openresty.org/package/centos/openresty.repo
        yum install -y openresty
    else
        echo "[!] Distro tidak dikenali. Install OpenResty manual:"
        echo "    https://openresty.org/en/linux-packages.html"
        exit 1
    fi
    echo "      [OK] OpenResty terinstall."
else
    echo "      [OK] OpenResty sudah ada: $(openresty -v 2>&1 | head -1)"
fi

# ---------------------------------------------------------------------------
# 2. Install Python dependencies
# ---------------------------------------------------------------------------
echo "[2/8] Menyiapkan virtual environment dan dependensi Python..."
VENV_DIR="$PROJECT_DIR/venv"

# Gunakan venv yang sudah ada, atau buat baru
if [ ! -f "$VENV_DIR/bin/python" ]; then
    echo "      Membuat venv di $VENV_DIR ..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

PYTHON_BIN="$VENV_DIR/bin/python"
PIP_BIN="$VENV_DIR/bin/pip"

"$PIP_BIN" install -q --upgrade pip
"$PIP_BIN" install -q -r "$PROJECT_DIR/requirements.txt"
echo "      [OK] Dependensi Python terinstall di venv."

# ---------------------------------------------------------------------------
# 3. Pindahkan Nginx OJS dari port 80 ke 127.0.0.1:8080
# ---------------------------------------------------------------------------
echo "[3/8] Memindahkan Nginx OJS dari port 80 ke 127.0.0.1:$OJS_NGINX_PORT..."

# Cari file konfigurasi Nginx yang listen di port 80
NGINX_OJS_CONF=""
for dir in /etc/nginx/sites-enabled /etc/nginx/conf.d /etc/nginx; do
    if [ -d "$dir" ]; then
        FOUND="$(grep -rl 'listen.*80' "$dir" 2>/dev/null | head -1 || true)"
        if [ -n "$FOUND" ]; then
            NGINX_OJS_CONF="$FOUND"
            break
        fi
    fi
done

if [ -z "$NGINX_OJS_CONF" ]; then
    echo "      [WARN] Tidak menemukan config Nginx dengan listen 80."
    echo "      Cari dan ubah manual: ganti 'listen 80' → 'listen 127.0.0.1:$OJS_NGINX_PORT'"
else
    echo "      Ditemukan: $NGINX_OJS_CONF"
    # Backup
    cp -n "$NGINX_OJS_CONF" "${NGINX_OJS_CONF}.bak.$(date +%Y%m%d%H%M%S)"
    # Ganti listen 80 (semua variasi) ke 127.0.0.1:8080
    sed -i \
        -e "s/listen\s\+0\.0\.0\.0:80\b/listen 127.0.0.1:$OJS_NGINX_PORT/" \
        -e "s/listen\s\+80\s*;/listen 127.0.0.1:$OJS_NGINX_PORT;/" \
        -e "s/listen\s\+80\s*default_server\s*;/listen 127.0.0.1:$OJS_NGINX_PORT default_server;/" \
        "$NGINX_OJS_CONF"
    echo "      [OK] Nginx OJS dipindah ke 127.0.0.1:$OJS_NGINX_PORT"
    nginx -t 2>&1 && systemctl reload nginx && echo "      [OK] Nginx OJS reload berhasil." \
        || echo "      [WARN] Nginx reload gagal — cek $NGINX_OJS_CONF manual."
fi

# ---------------------------------------------------------------------------
# 4. Buat direktori OpenResty conf.d jika belum ada
# ---------------------------------------------------------------------------
echo "[4/8] Menyiapkan konfigurasi OpenResty..."
mkdir -p "$OPENRESTY_SITES_DIR"
mkdir -p /var/log/openresty

# Pastikan openresty.conf meng-include conf.d
MAIN_CONF="$OPENRESTY_CONF_DIR/nginx.conf"
if [ -f "$MAIN_CONF" ] && ! grep -q 'conf\.d' "$MAIN_CONF"; then
    # Tambahkan include di dalam blok http
    sed -i '/^http\s*{/a\    include conf.d/*.conf;' "$MAIN_CONF"
    echo "      [OK] Ditambahkan include conf.d/*.conf ke $MAIN_CONF"
fi

# Salin konfigurasi WAF
cp "$SCRIPT_DIR/nginx_waf.conf" "$OPENRESTY_SITES_DIR/ojs_waf.conf"
echo "      [OK] nginx_waf.conf → $OPENRESTY_SITES_DIR/ojs_waf.conf"

# ---------------------------------------------------------------------------
# 5. Salin waf_checker.lua
# ---------------------------------------------------------------------------
echo "[5/8] Menyalin waf_checker.lua..."
cp "$SCRIPT_DIR/waf_checker.lua" "$OPENRESTY_CONF_DIR/waf_checker.lua"
echo "      [OK] waf_checker.lua → $OPENRESTY_CONF_DIR/waf_checker.lua"

# ---------------------------------------------------------------------------
# 6. Test dan start OpenResty
# ---------------------------------------------------------------------------
echo "[6/8] Mengaktifkan OpenResty di port $WAF_LISTEN_PORT..."
openresty -t 2>&1
systemctl enable openresty
systemctl restart openresty
echo "      [OK] OpenResty berjalan di $WAF_LISTEN_IP:$WAF_LISTEN_PORT"

# ---------------------------------------------------------------------------
# 7. Buat systemd service untuk sidecar_agent (Phase 1: --monitor)
# ---------------------------------------------------------------------------
echo "[7/8] Membuat systemd service waf-sidecar..."

# File konfigurasi sidecar (edit untuk Phase 2: hapus --monitor)
cat > /etc/default/waf-sidecar <<EOF
# Konfigurasi WAF Sidecar Agent
# Phase 1 (dataset collection): biarkan --monitor
# Phase 2 (enforcement): hapus flag --monitor setelah model dilatih
WAF_SIDECAR_OPTS="--monitor --host 127.0.0.1 --port $SIDECAR_PORT"
WAF_PROJECT_DIR="$PROJECT_DIR"
EOF

cat > /etc/systemd/system/waf-sidecar.service <<EOF
[Unit]
Description=OJS WAF Sidecar Agent (ML-Based, Bare Metal)
Documentation=file://$PROJECT_DIR/docs/architecture_plan.md
After=network.target

[Service]
Type=simple
User=$SIDECAR_USER
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=/etc/default/waf-sidecar
ExecStart=$PROJECT_DIR/venv/bin/python $PROJECT_DIR/core/sidecar_agent.py \$WAF_SIDECAR_OPTS
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=waf-sidecar

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable waf-sidecar
echo "      [OK] Service waf-sidecar dibuat dan di-enable."

# ---------------------------------------------------------------------------
# 8. Start sidecar
# ---------------------------------------------------------------------------
echo "[8/8] Memulai waf-sidecar (Phase 1 — monitor/record mode)..."
systemctl restart waf-sidecar
sleep 2

if systemctl is-active --quiet waf-sidecar; then
    echo "      [OK] waf-sidecar berjalan di 127.0.0.1:$SIDECAR_PORT"
else
    echo "      [FAIL] waf-sidecar gagal start. Cek log:"
    echo "         journalctl -u waf-sidecar -n 30"
    exit 1
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=========================================================="
echo "  Setup selesai!"
echo "=========================================================="
echo ""
echo "  Arsitektur aktif:"
echo "    Client → OpenResty :80 (0.0.0.0)"
echo "                 │ TCP :$SIDECAR_PORT"
echo "                 ▼"
echo "    sidecar_agent.py (Phase 1: record only)"
echo "                 │"
echo "                 ▼ PASS"
echo "    Nginx OJS :$OJS_NGINX_PORT (127.0.0.1) → PHP-FPM → OJS"
echo ""
echo "  Dataset CSV disimpan di:"
echo "    $PROJECT_DIR/dataset/raw/     ← semua request"
echo "    $PROJECT_DIR/dataset/labeled/ ← request + keputusan WAF"
echo ""
echo "  Cek status:"
echo "    systemctl status waf-sidecar"
echo "    journalctl -u waf-sidecar -f"
echo ""
echo "  Setelah dataset cukup, latih model:"
echo "    python -m ml_training.train_pipeline"
echo ""
echo "  Aktifkan Phase 2 (enforcement):"
echo "    sudo sed -i 's/--monitor //' /etc/default/waf-sidecar"
echo "    sudo systemctl restart waf-sidecar"
echo ""
