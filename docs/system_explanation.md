# ML-Based WAF System Explanation

## Purpose

Userspace Web Application Firewall (WAF) untuk Open Journal Systems (OJS)
yang berjalan di server bare metal (tanpa Docker).

OpenResty menjadi front-end di port 80, meneruskan setiap request ke Python
sidecar via TCP untuk inspeksi ML dan pencatatan dataset. Request clean
diteruskan ke Nginx OJS (port 8080). Request anomali di-DROP tanpa response.

Sistem tidak melakukan ban IP. Setiap request dievaluasi secara independen.

**Target:** OJS di `/var/www/ojs`, URL `http://10.34.100.110/`

## Deployment (Bare Metal)

```
Nginx OJS semula di :80  →  dipindah ke 127.0.0.1:8080 oleh setup_baremetal.sh
OpenResty dipasang di 0.0.0.0:80  →  menjadi WAF front-end
sidecar_agent.py berjalan di 127.0.0.1:9999  →  via systemd service waf-sidecar
```

```bash
sudo bash integrations/setup_baremetal.sh
```

## Active Runtime Components

### 1. OpenResty layer (port 80)

File utama:

- `integrations/waf_checker.lua`
- `integrations/nginx_waf.conf`
- `integrations/setup_baremetal.sh`

`waf_checker.lua` berjalan di fase `access_by_lua_file` Nginx. Untuk setiap
request yang tidak di-bypass, ia mengumpulkan:

- request id
- method
- URI dan query string
- headers
- request body, dibatasi 16 KB
- metadata source dan server address
- nilai cookie, authorization, dan X-Forwarded-For

Data dikirim sebagai satu JSON object diakhiri newline ke sidecar lewat TCP:

```text
host: 127.0.0.1   (loopback — bare metal, sidecar di host yang sama)
port: 9999
protocol: JSON Lines over TCP
```

Jika sidecar tidak tersedia, Lua **fail-open** dan meneruskan request (PASS).

### 2. Python sidecar WAF (port 9999)

File utama:

- `core/sidecar_agent.py`

Sidecar listen di TCP `127.0.0.1:9999`. Format pesan masuk:

```json
{
  "type": "REQUEST_CHECK",
  "request_id": "...",
  "method": "POST",
  "uri": "/index.php/ojs/login",
  "headers": {},
  "body": "username=admin&password=[MASKED]",
  "source_ip": "192.168.1.5"
}
```

Untuk setiap request, sidecar:

1. Ekstrak dan normalisasi field request
2. Hash cookie, strip nilai authorization token
3. Mask key sensitif di body (password, token, secret, dll.)
4. Tulis raw dataset record secara async
5. **Phase 1 (--monitor, tanpa model):** langsung return PASS, catat ke CSV
6. **Phase 2 (enforce, dengan model):** ekstrak fitur → Random Forest inference
7. Klasifikasi attack type dengan regex heuristic jika model prediksi BLOCK
8. Return `WAF_DECISION` ke Lua
9. Tulis labeled dataset record secara async

Default blocking threshold: `0.50`.

### 3. ML training dan model artifact

File aktif:

- `ml_training/train_pipeline.py`
- `ml_training/waf_model.pkl`

`train_pipeline.py` membuat synthetic dataset OJS-focused, mengekstrak fitur
numerik dari request, melatih `RandomForestClassifier`, mengevaluasi hasilnya,
dan menyimpan model bundle ke `ml_training/waf_model.pkl`.

Sidecar meng-import `extract_features` dari `ml_training/features.py`, sehingga
urutan fitur di file tersebut adalah **production feature contract**.

Kelompok fitur utama:

- panjang request dan payload
- entropy URI dan body
- jumlah karakter khusus
- jumlah pattern SQL injection, XSS, path traversal, command injection
- konteks URI spesifik OJS
- HTTP method berisiko
- anomali query string
- header tidak biasa atau tidak ada
- rasio non-ASCII di body
- request rate per source IP (rolling window 60 detik)

### 4. Dataset logging

Folder:

- `dataset/raw/`
- `dataset/labeled/`
- `dataset/meta/`

Sidecar menulis CSV harian:

- `dataset/raw/YYYY-MM-DD.csv` — request masuk, sanitized, tanpa label ML
- `dataset/labeled/YYYY-MM-DD.csv` — request + keputusan WAF

Kolom tambahan di labeled:

| Kolom | Keterangan |
|-------|------------|
| `decision` | `PASS` atau `BLOCK` (keputusan model, bukan override monitor) |
| `threat_score` | Probabilitas attack dari Random Forest (0.0–1.0) |
| `confidence` | Confidence score inference |
| `attack_type` | `SQL_INJECTION`, `XSS`, `PATH_TRAVERSAL`, `COMMAND_INJECTION`, `NONE` |
| `model_version` | Versi bundle model yang dipakai |

## Request Flow

```
Client
  → OpenResty 0.0.0.0:80
  → waf_checker.lua access phase
  → TCP JSONL REQUEST_CHECK → 127.0.0.1:9999
  → core/sidecar_agent.py
      [Phase 1] tulis CSV, return PASS
      [Phase 2] ml_training/features.py extract_features()
              → ml_training/waf_model.pkl Random Forest inference
              → WAF_DECISION
  → waf_checker.lua enforcement
      PASS  → proxy ke Nginx OJS 127.0.0.1:8080 → PHP-FPM → /var/www/ojs
      BLOCK → ngx.exit(444) DROP koneksi
```

Alur detail:

1. Client kirim HTTP request ke `10.34.100.110:80`.
2. `waf_checker.lua` skip: `/health`, `/robots.txt`, `/favicon.ico`, `OPTIONS`.
3. Lua bangun objek JSON `REQUEST_CHECK`.
4. Lua kirim ke sidecar Python di `127.0.0.1:9999`.
5. Sidecar sanitize + mask data sensitif.
6. Sidecar tulis raw record ke antrian CSV.
7. **Phase 1:** sidecar langsung kirim PASS (model belum ada).
8. **Phase 2:** hitung 15 fitur → Random Forest → `threat_score`.
9. `threat_score >= 0.50` → `decision = BLOCK`, sebaliknya `PASS`.
10. Monitor mode: simpan real decision di CSV, tapi kirim PASS ke Lua.
11. Sidecar tulis labeled record ke antrian CSV.
12. Lua eksekusi decision dari sidecar.

## Operating Modes

### Phase 1 — Monitor mode (dataset collection)

```bash
# Status service
systemctl status waf-sidecar

# Log real-time
journalctl -u waf-sidecar -f

# Lihat CSV yang terkumpul
ls -lh dataset/raw/
```

- Model ML **tidak wajib ada**.
- Semua traffic dicatat ke CSV.
- Tidak ada request yang diblokir.

### Phase 2 — Enforce mode (setelah model dilatih)

```bash
# Latih model
python -m ml_training.train_pipeline

# Aktifkan enforce
sudo sed -i 's/--monitor //' /etc/default/waf-sidecar
sudo systemctl restart waf-sidecar
```

- `threat_score >= 0.50` → `ngx.exit(444)` DROP.
- Semua keputusan tetap dicatat ke CSV.

## Design Notes

- Sidecar protocol: TCP JSON Lines, bukan Unix domain socket.
- `core/blocking_mechanism.py` adalah stub kompatibilitas — blocking dilakukan
  oleh Nginx/Lua, bukan kernel atau eBPF.
- Sidecar listen di `127.0.0.1:9999` (loopback only) — tidak terekspos ke network.
- Nginx OJS hanya bisa diakses dari loopback (`127.0.0.1:8080`).
- Dataset CSV hanya berisi data yang sudah di-sanitize dan di-mask.

