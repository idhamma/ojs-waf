# Pelatihan Data Nyata (tanpa merge.csv) & Dashboard Monitoring

Dokumen ini menjelaskan jalur yang **benar-benar diimplementasikan**: melatih
model dari gabungan file `labeled/` secara langsung (tanpa `merge.csv`), dengan
penyesuaian fitur agar sesuai dataset, plus dashboard web untuk monitoring WAF.

Untuk latar belakang desain berbasis `merge.csv`, lihat
[`using_real_dataser.md`](using_real_dataser.md). Catatan di bawah menjelaskan
mengapa pendekatan langsung ini dipilih.

---

## 1. Mengapa bukan `merge.csv`?

`merge.csv` adalah keluaran skrip merge yang sengaja:

1. **Menciutkan 31–33 kolom** capture asli menjadi **11 kolom kanonik** — semua
   kolom seperti `user_agent`, `content_type`, `referer`, dan `response_*`
   dibuang. Inilah "parameter yang hilang".
2. **Menetralkan** `source_ip` & `headers_raw` jadi konstan (anti-kebocoran).
3. **Men-dedup** payload (7.246 → 5.956 baris).

Jadi hilangnya parameter itu *by design*, bukan bug. Karena kita ingin
mempertahankan kolom asli dan menangani kebocoran dengan cara lain, kita baca
file `labeled/` langsung.

## 2. Isi dataset

Hanya tiga kelas — **RCE**, **XSS**, **Normal**. Tidak ada SQLi, path
traversal, maupun command injection.

| File | Isi |
|------|-----|
| `12-06-2026_labeled_1.csv` | RCE (rute `NativeImportExportPlugin`) + Normal |
| `12-06-2026_labeled_2.csv` | XSS (payload di body `$$$call$$$`) + Normal |
| `normal_labeled.csv` | Normal |

Setelah dedup: **5.953 baris** (RCE 3.000, XSS 1.326, Normal 1.627).

## 3. Penyesuaian fitur (33 → 22)

`extract_features` tetap menghasilkan 33 fitur (ekstraktor tidak diubah, tes
regex & pipeline sintetis tetap jalan), tetapi **model dilatih & inferensi
hanya memakai 22 fitur** (`REALDATA_FEATURE_NAMES` di `ml_training/features.py`).

**11 fitur dibuang** (`DROPPED_FEATURE_NAMES`):

- *Famili serangan yang tidak ada di data* — `sql_keyword_count`,
  `sql_metachar_count`, `sql_tautology`, `sql_time_based`,
  `path_traversal_count`, `command_inj_count`.
- *Kebocoran IP/User-Agent* (semua serangan dari satu IP+UA) — `req_rate`,
  `bot_user_agent`, `user_agent_length`, `missing_user_agent`,
  `missing_host_header`. Membuang ini setara dengan—tetapi lebih sederhana
  daripada—menetralkan kolomnya, dan tidak butuh tahap merge.

Bundle model menyimpan `feature_names = REALDATA_FEATURE_NAMES`; sidecar
membangun proyeksi 33→22 yang sama saat load, sehingga parity terverifikasi
ujung-ke-ujung.

## 4. Cara menjalankan

```bash
# Setup
python -m venv venv && ./venv/bin/pip install -r requirements.txt

# Lihat ringkasan data gabungan
./venv/bin/python -m ml_training.data_loader

# Latih model (tanpa merge.csv, fitur 22, attack_types=[RCE,XSS])
./venv/bin/python -m ml_training.train_on_real
# opsi: --no-dedup, --seed 7, --max-depth 12

# Tes
./venv/bin/python -m pytest tests/ -q
```

Keluaran tersimpan ke `ml_training/waf_model.pkl`.

## 5. Catatan jujur untuk skripsi (PENTING)

Pada split uji, model mencapai precision/recall/F1 ≈ **1.00**. **Angka ini
harus dibaca hati-hati**: serangan tangkapan sangat homogen secara struktur
(semua RCE dari satu rute import; semua XSS dari satu rute `$$$call$$$` dengan
body besar), sehingga kelas terpisah secara trivial lewat fitur struktural
(`uri_len`, `path_depth`, `num_slashes`, `body_len`).

Bukti keterbatasan ini ada di **smoke test** `train_on_real`: payload XSS/RCE
yang sedikit berbeda dari distribusi pelatihan **lolos** (mis. RCE body kecil).
Artinya model belajar bentuk rute/ukuran, bukan sepenuhnya semantik payload.

Rekomendasi untuk bab metodologi:

- Laporkan precision/recall/F1 **per kelas**, bukan akurasi telanjang.
- Sajikan tabel `feature_importance` (dicetak otomatis) sebagai bukti fitur mana
  yang dipakai — dan diskusikan dominasi fitur struktural.
- Nyatakan eksplisit cakupan klaim: **hanya XSS dan RCE**.
- Untuk generalisasi lebih baik, kumpulkan serangan dari beberapa IP/UA dan
  variasi payload (mis. sqlmap/ffuf yang sudah ada di tooling), lalu latih ulang.

## 6. Dashboard monitoring (`tools/waf_streamlit.py`)

Web interaktif berbasis Streamlit + Plotly yang membaca log harian sidecar di
`dataset/labeled/YYYY-MM-DD.csv`.

```bash
./venv/bin/streamlit run tools/waf_streamlit.py
# akses non-lokal (hanya di jaringan tepercaya):
./venv/bin/streamlit run tools/waf_streamlit.py --server.address 0.0.0.0 --server.port 8501
```

Menampilkan:

- KPI: total / blocked / passed / block-rate / jumlah IP unik.
- Kesehatan host: CPU, memori, load average, throughput jaringan (`/proc`).
- Grafik lalu lintas dari waktu ke waktu (passed vs blocked), per menit/jam.
- Breakdown tipe serangan, donut PASS/BLOCK, histogram threat-score.
- Top source IP yang diblokir.
- Tabel log event yang bisa difilter, dicari, dan diunduh (CSV).

> Dashboard HTTP stdlib lama (`tools/waf_dashboard.py`) tetap ada sebagai
> alternatif ringan tanpa dependensi tambahan.
