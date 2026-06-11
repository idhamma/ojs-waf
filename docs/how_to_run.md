# Cara Menjalankan ML-Based WAF

Target: OJS di `/var/www/ojs`, URL `http://10.34.100.110/`

## Prasyarat

- Server Ubuntu/Debian dengan OJS berjalan di Nginx port 80
- Python 3.8+
- Akses root (sudo)

```bash
# Clone/copy project ke server
cd /home/waf/ojs-waf
source .venv/bin/activate

# Install dependensi Python
pip3 install -r requirements.txt
```

---

## Opsi A — Setup Otomatis (Recommended)

Satu perintah mengerjakan segalanya:

```bash
sudo bash integrations/setup_baremetal.sh
```

Yang dilakukan secara otomatis:
1. Install OpenResty via package manager
2. Install dependensi Python
3. Pindahkan Nginx OJS: `0.0.0.0:80` → `127.0.0.1:8080` (backup config lama)
4. Deploy `nginx_waf.conf` ke `/etc/openresty/conf.d/ojs_waf.conf`
5. Deploy `waf_checker.lua` ke `/etc/openresty/waf_checker.lua`
6. Start OpenResty di `0.0.0.0:80`
7. Buat dan start systemd service `waf-sidecar` (Phase 1: `--monitor`)

Setelah selesai, WAF langsung aktif dalam **Phase 1** — semua traffic direkam ke CSV, tidak ada yang diblokir.

---

## Opsi B — Manual Step by Step

### 1. Install OpenResty

```bash
# Ubuntu/Debian
curl -fsSL https://openresty.org/package/pubkey.gpg \
    | sudo gpg --dearmor -o /usr/share/keyrings/openresty.gpg

echo "deb [signed-by=/usr/share/keyrings/openresty.gpg] \
    http://openresty.org/package/ubuntu $(lsb_release -sc) main" \
    | sudo tee /etc/apt/sources.list.d/openresty.list

sudo apt update && sudo apt install -y openresty
```

### 2. Pindahkan Nginx OJS ke port 8080

```bash
# Cari config nginx yang listen di port 80
grep -rl 'listen.*80' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/

# Edit file yang ditemukan, ganti:
#   listen 80;              → listen 127.0.0.1:8080;
#   listen 0.0.0.0:80;     → listen 127.0.0.1:8080;

sudo nano /etc/nginx/sites-enabled/<nama-file>

# Reload nginx
sudo nginx -t && sudo systemctl reload nginx
```

### 3. Deploy konfigurasi WAF

```bash
sudo mkdir -p /etc/openresty/conf.d
sudo cp integrations/nginx_waf.conf /etc/openresty/conf.d/ojs_waf.conf
sudo cp integrations/waf_checker.lua /etc/openresty/waf_checker.lua
sudo openresty -t && sudo systemctl restart openresty
```

### 4. Jalankan sidecar — Phase 1 (record only)

```bash
# Foreground (untuk testing)
python3 core/sidecar_agent.py --monitor

# Background via systemd (production)
sudo systemctl start waf-sidecar
```

---

## Arsitektur Setelah Setup

```
Client
  │ HTTP :80
  ▼
OpenResty (0.0.0.0:80)   ← WAF front-end
  waf_checker.lua
  │ TCP :9999
  ▼
sidecar_agent.py (127.0.0.1:9999)
  │
  ├── PASS  → Nginx OJS (127.0.0.1:8080) → PHP-FPM → /var/www/ojs
  └── BLOCK → ngx.exit(444) DROP
```

---

## Cek Status

```bash
# Status service sidecar
systemctl status waf-sidecar

# Log traffic real-time
journalctl -u waf-sidecar -f

# Lihat CSV yang terekam (dibuat per hari)
ls -lh dataset/raw/
ls -lh dataset/labeled/

# Test WAF endpoint health
curl http://10.34.100.110/health
```

---

## Phase 1 — Monitor / Record Mode

Sidecar **hanya merekam** traffic ke CSV tanpa memblokir apapun.
Model ML tidak diperlukan di fase ini.

Dataset tersimpan di:
- `dataset/raw/YYYY-MM-DD.csv` — semua request masuk
- `dataset/labeled/YYYY-MM-DD.csv` — request + keputusan WAF

```bash
# Pastikan sidecar berjalan dalam monitor mode
grep WAF_SIDECAR_OPTS /etc/default/waf-sidecar
# Harus ada flag: --monitor
```

---

## Phase 2 — Enforce Mode (setelah dataset cukup)

### Latih model

```bash
python3 -m ml_training.train_pipeline
# Model tersimpan di: ml_training/waf_model.pkl
```

### Aktifkan blocking

```bash
sudo sed -i 's/--monitor //' /etc/default/waf-sidecar
sudo systemctl restart waf-sidecar

# Verifikasi enforce mode aktif
grep WAF_SIDECAR_OPTS /etc/default/waf-sidecar
# Flag --monitor sudah tidak ada
```

Setelah ini, request dengan `threat_score >= 0.50` akan di-DROP (`ngx.exit(444)`).

---

## Rollback

```bash
# Kembalikan Nginx OJS ke port 80
sudo cp /etc/nginx/sites-enabled/<file>.bak.<timestamp> /etc/nginx/sites-enabled/<file>
sudo nginx -t && sudo systemctl reload nginx

# Hentikan WAF
sudo systemctl stop waf-sidecar
sudo systemctl stop openresty
```
