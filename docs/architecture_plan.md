# Arsitektur Sistem: ML-Based WAF (Userspace) — OJS

## Ringkasan

WAF berbasis Machine Learning yang beroperasi sepenuhnya di **Userspace**.
Menggunakan Random Forest Classifier untuk mendeteksi anomali payload HTTP.
Blocking = **DROP** (koneksi diputus tanpa response, tanpa ban IP).

## Komponen

```
Client ──HTTP──▶ Docker [OpenResty + waf_checker.lua]
                         │
                         │ TCP :9999 (JSON)
                         ▼
                 Host [sidecar_agent.py → Random Forest]
                         │
                         ▼
                 Docker [PHP-FPM → OJS]  (jika PASS)
                 Client  ← DROP 444      (jika BLOCK)
```

### 1. Data Plane (Docker Container)
- **OpenResty** (Nginx + LuaJIT) sebagai web server
- **waf_checker.lua** mencegat setiap request pada fase `access_by_lua`
- Mengirim `REQUEST_CHECK` (JSON) ke sidecar via TCP
- Menerima `WAF_DECISION` dan mengeksekusi:
  - `PASS` → forward ke PHP-FPM/OJS
  - `BLOCK` → `ngx.exit(444)` — DROP koneksi tanpa response

### 2. Control Plane (Host Machine)
- **sidecar_agent.py** — Python daemon listening TCP :9999
- **Random Forest** (scikit-learn, 100 trees, max_depth=10)
- **15 fitur numerik** diekstrak dari URI + Body + Headers
- **Dataset Writer** — CSV logger async (raw + labeled, rotasi harian)

### 3. Komunikasi
- **Transport:** TCP socket (host:9999 ← container via 172.17.0.1)
- **Format:** JSON Lines (satu objek JSON per baris, terminated `\n`)
- **Mode:** Synchronous — Lua menunggu respons sebelum lanjut

## Alur Eksekusi

1. **Ingestion**: Lua extract URI, Headers, Body dari HTTP request
2. **Sanitization**: Sidecar mask data sensitif (password, token)
3. **Feature Extraction**: 15 fitur numerik dari teks mentah
4. **Inference**: `model.predict(X)` → prediksi + probabilitas
5. **Decision**: probabilitas ≥ 0.70 → BLOCK, else → PASS
6. **Enforcement**: Lua eksekusi DROP (444) atau forward ke upstream
7. **Logging**: Dataset CSV ditulis async oleh background thread

## Mode Operasi

| Mode | Flag | Perilaku |
|------|------|----------|
| **Enforce** | (default) | BLOCK anomali (DROP), PASS normal |
| **Monitor** | `--monitor` | Log semua keputusan, selalu PASS (untuk dataset collection) |

Dalam mode monitor, field `decision` di dataset labeled berisi keputusan REAL
(BLOCK/PASS) untuk menghasilkan training data yang akurat.
