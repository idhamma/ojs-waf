# Arsitektur Sistem: ML-Based WAF (Bare Metal) — OJS

## Ringkasan

WAF berbasis Machine Learning yang beroperasi sepenuhnya di **Userspace**,
deploy langsung di server bare metal tanpa Docker.
Menggunakan Random Forest Classifier untuk mendeteksi anomali payload HTTP.
Blocking = **DROP** (koneksi diputus tanpa response, tanpa ban IP).

Target: OJS di `/var/www/ojs`, URL `http://10.34.100.110/`

## Komponen

```
Client
  │
  │ HTTP :80
  ▼
OpenResty (0.0.0.0:80)       ← WAF front-end
  waf_checker.lua
  │
  │ TCP :9999  JSON
  ▼
sidecar_agent.py (127.0.0.1:9999)
  Random Forest / Monitor mode
  CSV Logger
  │
  ├──▶ PASS → Nginx OJS (127.0.0.1:8080)
  │              └─▶ PHP-FPM → OJS (/var/www/ojs)
  └──▶ BLOCK → ngx.exit(444)  DROP tanpa response
```

### 1. Data Plane — OpenResty (port 80)

| Komponen | File | Keterangan |
|---|---|---|
| Config Nginx | `integrations/nginx_waf.conf` | Upstream ke Nginx OJS :8080 |
| WAF Lua | `integrations/waf_checker.lua` | Intercept tiap request, kirim ke sidecar |
| Setup script | `integrations/setup_baremetal.sh` | Install + konfigurasi otomatis |

- **OpenResty** listen di `0.0.0.0:80` — menggantikan posisi Nginx OJS.
- `waf_checker.lua` mencegat setiap request pada fase `access_by_lua_file`.
- Mengirim `REQUEST_CHECK` (JSON) ke sidecar via TCP `:9999`.
- Menerima `WAF_DECISION` dan mengeksekusi:
  - `PASS` → forward ke Nginx OJS (`127.0.0.1:8080`)
  - `BLOCK` → `ngx.exit(444)` — DROP koneksi tanpa response
- **Fail-open**: jika sidecar tidak tersedia, request tetap diteruskan (PASS).

### 2. Control Plane — Python Sidecar (port 9999)

| Komponen | File | Keterangan |
|---|---|---|
| Sidecar agent | `core/sidecar_agent.py` | TCP daemon, ML inference, CSV logger |
| Blocking stub | `core/blocking_mechanism.py` | TTL classifier per attack type |
| Systemd service | `/etc/systemd/system/waf-sidecar.service` | Auto-start di boot |
| Konfigurasi | `/etc/default/waf-sidecar` | Flag mode (--monitor / enforce) |

- **sidecar_agent.py** — Python daemon listening TCP `127.0.0.1:9999`.
- **Phase 1 (Monitor)**: model ML tidak wajib ada — sidecar hanya merekam traffic ke CSV.
- **Phase 2 (Enforce)**: Random Forest (scikit-learn, 100 trees), block threshold `0.50`.
- **Dataset Writer** — CSV logger async dengan background thread, rotasi harian.

### 3. OJS Upstream — Nginx OJS (port 8080)

- Nginx OJS yang semula di port 80 **dipindahkan** ke `127.0.0.1:8080` oleh `setup_baremetal.sh`.
- Hanya bisa diakses dari loopback — tidak terekspos langsung ke internet.
- PHP-FPM tetap melayani OJS dari `/var/www/ojs` seperti biasa.

## Fase Operasi

### Phase 1 — Dataset Collection (Monitor Mode)

Tujuan: rekam semua traffic HTTP ke CSV tanpa memblokir apapun.

```
systemctl status waf-sidecar       # pastikan berjalan
journalctl -u waf-sidecar -f       # lihat traffic real-time
ls dataset/raw/                    # CSV harian tersimpan di sini
```

Pada mode ini:
- Model ML **tidak diperlukan** — sidecar tetap jalan meski `waf_model.pkl` belum ada.
- Semua request dicatat ke `dataset/raw/YYYY-MM-DD.csv` dan `dataset/labeled/YYYY-MM-DD.csv`.
- Semua keputusan adalah PASS (tidak ada blocking).
- Field `decision` di labeled CSV berisi `PASS` (karena belum ada model).

### Phase 2 — Enforcement (setelah model dilatih)

Tujuan: blokir request anomali secara real-time.

```bash
# 1. Latih model dari dataset yang sudah terkumpul
python -m ml_training.train_pipeline

# 2. Aktifkan enforce mode
sudo sed -i 's/--monitor //' /etc/default/waf-sidecar
sudo systemctl restart waf-sidecar
```

Pada mode ini:
- `threat_score >= 0.50` → BLOCK (koneksi di-DROP, `ngx.exit(444)`)
- `threat_score < 0.50` → PASS (diteruskan ke Nginx OJS)
- Semua keputusan tetap dicatat ke CSV untuk retraining.

## Alur Eksekusi Detail

```
1. Client kirim HTTP request ke 10.34.100.110:80
2. OpenResty terima request
3. waf_checker.lua: skip jika /health, /robots.txt, /favicon.ico, OPTIONS
4. waf_checker.lua: extract method, URI, headers, body (max 16KB)
5. Kirim REQUEST_CHECK JSON ke 127.0.0.1:9999
6. sidecar_agent.py: sanitize + mask data sensitif (password, token, cookie)
7. sidecar_agent.py: tulis raw record ke CSV (background thread)
8. sidecar_agent.py: extract 15 fitur numerik
9. [Phase 1] Return PASS langsung (no model)
   [Phase 2] Random Forest inference → threat_score
             threshold >= 0.50 → decision = BLOCK
             threshold <  0.50 → decision = PASS
10. Kirim WAF_DECISION JSON kembali ke Lua
11. sidecar_agent.py: tulis labeled record ke CSV
12. [PASS]  Lua forward ke upstream Nginx OJS :8080
13. [BLOCK] Lua ngx.exit(444) — DROP koneksi
```

## Dataset Output

| Folder | Isi | Update |
|--------|-----|--------|
| `dataset/raw/YYYY-MM-DD.csv` | Semua request masuk (tanpa label ML) | Setiap request |
| `dataset/labeled/YYYY-MM-DD.csv` | Request + keputusan WAF (decision, threat_score, attack_type) | Setiap request |
| `dataset/meta/schema_v3.json` | Skema kolom CSV | Statis |

File CSV berotasi setiap hari (UTC). Header ditulis otomatis pada baris pertama.

## Komunikasi Sidecar

| Parameter | Nilai |
|-----------|-------|
| Transport | TCP socket |
| Host | `127.0.0.1` (loopback) |
| Port | `9999` |
| Format | JSON Lines (1 objek JSON per baris, diakhiri `\n`) |
| Mode | Synchronous — Lua menunggu respons sebelum lanjut |
| Timeout | 2000ms (fail-open jika timeout) |

### Request (`REQUEST_CHECK`)
```json
{
  "type": "REQUEST_CHECK",
  "request_id": "abc123",
  "method": "POST",
  "uri": "/index.php/ojs/login",
  "query_string": "",
  "headers": { "host": "10.34.100.110", "user-agent": "..." },
  "body": "username=admin&password=[MASKED]",
  "source_ip": "192.168.1.5",
  "source_port": 54321,
  "server_ip": "10.34.100.110",
  "server_port": 80
}
```

### Response (`WAF_DECISION`)
```json
{
  "type": "WAF_DECISION",
  "request_id": "abc123",
  "decision": "PASS",
  "threat_score": 0.12,
  "confidence": 0.88,
  "attack_type": "NONE",
  "model_version": "rf-realistic-v1"
}
```

## Mode Operasi

| Mode | Flag | Model diperlukan | Perilaku |
|------|------|-----------------|----------|
| **Monitor** | `--monitor` | Tidak | Rekam semua traffic ke CSV, selalu PASS |
| **Enforce** | (default) | Ya | BLOCK anomali (DROP 444), PASS normal |

## Instalasi

```bash
# Clone/siapkan project
cd /home/waf/ojs-waf

# Jalankan setup otomatis (sebagai root)
sudo bash integrations/setup_baremetal.sh
```

Script akan:
1. Install OpenResty via package manager
2. Install dependensi Python (`requirements.txt`)
3. Pindahkan listen Nginx OJS: `0.0.0.0:80` → `127.0.0.1:8080` (backup config lama)
4. Deploy `nginx_waf.conf` ke `/etc/openresty/conf.d/ojs_waf.conf`
5. Deploy `waf_checker.lua` ke `/etc/openresty/waf_checker.lua`
6. Start OpenResty di `0.0.0.0:80`
7. Buat dan start systemd service `waf-sidecar` (Phase 1: `--monitor`)

## File Konfigurasi Penting

| File | Fungsi |
|------|--------|
| `integrations/nginx_waf.conf` | Konfigurasi OpenResty + upstream Nginx OJS |
| `integrations/waf_checker.lua` | Lua interceptor + komunikasi sidecar |
| `integrations/setup_baremetal.sh` | Script instalasi otomatis |
| `core/sidecar_agent.py` | Python sidecar daemon |
| `/etc/default/waf-sidecar` | Flag mode systemd service (edit untuk ganti phase) |
| `ml_training/waf_model.pkl` | Model Random Forest (dibuat oleh train_pipeline) |
| `dataset/raw/` | CSV traffic harian (tanpa label) |
| `dataset/labeled/` | CSV traffic harian + keputusan WAF |

