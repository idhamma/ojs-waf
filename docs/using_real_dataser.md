# Arsitektur Pelatihan Model WAF OJS (Data Nyata)

> Brief implementasi untuk Claude Code. Repo target: `github.com/idhamma/ojs-waf`.
> Tujuan: menambahkan jalur pelatihan berbasis data tangkapan nyata di atas
> kode yang sudah ada, dengan kontrol kebocoran (leakage), tanpa merusak
> kontrak runtime sidecar.

---

## 1. Konteks

Saat ini `ml_training/train_pipeline.py` hanya melatih dari data sintetis hasil
`dataset_generator` dan tidak pernah membaca CSV. Sudah tersedia tiga file
tangkapan nyata berlabel yang harus menjadi sumber pelatihan dan evaluasi:

| File | Baris mentah | Isi |
|------|-------------:|-----|
| `12-06-2026_labeled_1.csv` | 4.040 | RCE 3.000, Normal 1.040 |
| `12-06-2026_labeled_2.csv` | 1.329 | XSS 1.326, Normal 3 |
| `normal_labeled.csv` | 1.877 | Normal 1.877 |

Analisis data menemukan tiga masalah yang menentukan desain ini:

1. **Hanya dua famili serangan nyata**, yaitu RCE (penyalahgunaan
   `NativeImportExportPlugin/import`) dan XSS (payload di POST body pada route
   `$$$call$$$/.../update-query`). Tidak ada SQLi, path traversal, maupun
   command injection. Klaim thesis dibatasi ke XSS dan RCE saja.
2. **Payload XSS berada di body POST**, bukan di URI atau query. Detektor regex
   pada `features.py` hanya menangkap sekitar 65% payload XSS karena banyak
   yang ter-encode dengan entitas HTML berlapis. Random Forest tetap dapat
   belajar dari fitur statistik (entropy, panjang body, rasio non-ASCII).
3. **Kebocoran metadata parah.** Seluruh 4.326 serangan berasal dari satu IP
   (`172.19.2.40`) dengan satu User-Agent, sedangkan benign dari IP dan UA lain.
   Tanpa penanganan, model akan mencapai akurasi semu mendekati 100% dengan
   menghafal IP atau UA, bukan mengenali payload.

Tool `tools/merge_datasets.py` sudah dibuat untuk mengatasi poin 3 dan
menormalkan label. Output bakunya: **5.956 baris** setelah deduplikasi (RCE
3.000, BENIGN 1.630, XSS 1.326), dengan `req_rate` ternetralkan ke konstan 1
dan `headers_raw` ke satu nilai identik.

---

## 2. Prinsip & Invariant (tidak boleh dilanggar)

- **Parity 33 fitur.** Vektor fitur tetap 33-dim sesuai `FEATURE_NAMES` di
  `ml_training/features.py`. Bundle model menyimpan `feature_names` dan sidecar
  memverifikasinya saat load. Jangan menghapus kolom fitur; kebocoran ditangani
  dengan menetralkan input, bukan mengubah dimensi.
- **Netralisasi, bukan penghapusan.** `source_ip` dan `headers_raw` dinetralkan
  di tahap data prep sehingga lima fitur turunan (`req_rate`, `bot_user_agent`,
  `user_agent_length`, `missing_user_agent`, `missing_host_header`) bervarians
  nol dan otomatis mendapat importance mendekati nol dari Random Forest.
- **Determinisme.** `extract_features` adalah fungsi murni. Hasil pelatihan dan
  runtime harus identik untuk request yang sama. `random_state=42` di mana pun.
- **Cakupan klaim.** `attack_types` pada bundle hanya `["XSS", "RCE"]`. Tidak
  ada klaim deteksi SQLi, path traversal, atau command injection di kode maupun
  laporan, karena tidak ada datanya.
- **Pelaporan jujur.** Metrik utama adalah precision, recall, dan F1 per kelas,
  bukan akurasi telanjang, karena setelah dedup benign menjadi minoritas
  (27,4%). `class_weight="balanced"` dipertahankan.
- **Keamanan runtime.** Panjang body dan query dibatasi sebelum regex untuk
  mencegah catastrophic backtracking pada `_CMD_INJ` yang dapat membuat sidecar
  membeku saat menerima body besar.

---

## 3. Arsitektur & Alur Data

```
   Tangkapan nyata (CSV berlabel)
   labeled_1.csv  labeled_2.csv  normal_labeled.csv
                  │
                  ▼
   ┌─────────────────────────────────────────────┐
   │ tools/merge_datasets.py                       │
   │  - petakan label  (Normal/RCE/XSS)            │
   │  - dedup payload  (cegah kontaminasi split)   │
   │  - batasi panjang body & query                │
   │  - netralkan source_ip + headers_raw          │
   └─────────────────────────────────────────────┘
                  │
                  ▼
   dataset/real/merged_dataset.csv   (skema kanonik)
                  │
                  ▼
   ┌─────────────────────────────────────────────┐
   │ ml_training/data_loader.py   (BARU)           │
   │  - baca CSV ke DataFrame                       │
   │  - panggil build_feature_matrix (reuse)        │
   │  - kembalikan X[N×33], y, attack_labels        │
   └─────────────────────────────────────────────┘
                  │
                  ▼
   ┌─────────────────────────────────────────────┐
   │ ml_training/train_on_real.py   (BARU)         │
   │  - stratified 80/20 (stratify per attack_type)│
   │  - RandomForest(200, depth14, balanced, rs42) │
   │  - threshold sweep F1 (0.30–0.95)             │
   │  - laporan per-attack recall + confusion mat. │
   │  - laporan feature_importance (bukti anti-bocor)│
   │  - smoke tests (reuse dari train_pipeline)     │
   └─────────────────────────────────────────────┘
                  │
                  ▼
   ml_training/waf_model.pkl
   { model, feature_names, block_threshold,
     attack_types=["XSS","RCE"], model_version, trained_at }
                  │
                  ▼
   ┌─────────────────────────────────────────────┐
   │ core/sidecar_agent.py  (SidecarWAF)           │
   │  - load bundle, verifikasi feature_names      │
   │  - predict() runtime via TCP 9999             │
   └─────────────────────────────────────────────┘
```

Prinsip pemisahan: ingestion (merge) terpisah dari pemuatan fitur (loader)
terpisah dari pelatihan (trainer). Generator sintetis lama tetap ada dan dipakai
hanya untuk smoke test dan augmentasi opsional, tidak lagi sebagai sumber utama.

---

## 4. Perubahan pada Pohon Repo

```
ojs-waf/
├── core/
│   └── sidecar_agent.py          # UBAH: parity-check & baca block_threshold dari bundle
├── ml_training/
│   ├── features.py               # UBAH kecil: cap panjang input sebelum regex
│   ├── train_pipeline.py         # TETAP (jalur sintetis, dipakai smoke test)
│   ├── dataset_generator.py      # TETAP
│   ├── data_loader.py            # BARU
│   └── train_on_real.py          # BARU (entrypoint pelatihan data nyata)
├── dataset/
│   └── real/
│       └── merged_dataset.csv    # BARU (output merge_datasets.py)
├── tools/
│   └── merge_datasets.py         # PINDAHKAN ke sini (sudah dibuat)
└── tests/
    └── test_train_on_real.py     # BARU (uji invariant)
```

---

## 5. Spesifikasi Modul

### 5.1 `ml_training/data_loader.py` (baru)

Tanggung jawab tunggal: ubah `merged_dataset.csv` menjadi matriks fitur, dengan
memakai ulang `build_feature_matrix` yang sudah ada agar perhitungan `req_rate`
(jendela 60 detik per IP) identik dengan runtime.

```python
def load_real_dataset(csv_path: Path) -> pd.DataFrame
    # baca CSV, pastikan kolom kanonik ada, kembalikan DataFrame siap pakai

def build_xy(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray]
    # delegasi ke ml_training.train_pipeline.build_feature_matrix
    # kembalikan (X, y, attack_labels)
```

Kolom yang dibutuhkan dari CSV: `timestamp`, `source_ip`, `method`, `uri`,
`query_string`, `body_truncated`, `headers_raw`, `decision`, `attack_type`.
`build_feature_matrix` memetakan `decision == "BLOCK"` ke label 1.

### 5.2 `ml_training/train_on_real.py` (baru, entrypoint)

Struktur mengikuti `run_pipeline` di `train_pipeline.py`, tetapi sumber data dari
loader, bukan generator.

```python
@dataclass(frozen=True)
class RealTrainingConfig:
    csv_path: Path
    n_estimators: int = 200
    max_depth: int = 14
    seed: int = 42
    test_size: float = 0.20
    default_threshold: float = 0.50

def run(config: RealTrainingConfig) -> None:
    df = load_real_dataset(config.csv_path)
    X, y, attack_labels = build_xy(df)
    assert X.shape[1] == NUM_FEATURES          # invariant 33-dim

    strat = np.where(y == 1, attack_labels, "BENIGN")
    X_tr, X_te, y_tr, y_te, atk_tr, atk_te = train_test_split(
        X, y, attack_labels,
        test_size=config.test_size, random_state=config.seed, stratify=strat,
    )

    clf = RandomForestClassifier(
        n_estimators=config.n_estimators, max_depth=config.max_depth,
        class_weight="balanced", random_state=config.seed, n_jobs=-1,
    )
    clf.fit(X_tr, y_tr)
    proba = clf.predict_proba(X_te)[:, 1]

    # laporan default + threshold sweep (reuse fungsi dari train_pipeline)
    best_t = threshold_sweep(y_te, proba)
    report_feature_importance(clf, FEATURE_NAMES)   # BUKTI anti-kebocoran
    print_per_attack_recall(atk_te, y_te, (proba >= best_t).astype(int))
    run_smoke_tests(clf, best_t)

    save_bundle(clf, best_t, attack_types=["XSS", "RCE"])
```

Fungsi baru `report_feature_importance` mencetak importance terurut dan
**menegaskan** bahwa kelima fitur bocor bernilai mendekati nol. Ini artefak
kunci untuk pembelaan sidang.

### 5.3 `ml_training/features.py` (ubah kecil)

Tambahkan pembatas panjang di awal `extract_features` sebelum operasi regex:

```python
MAX_SCAN_LEN = 8192
uri  = (uri or "")[:MAX_SCAN_LEN]
body = (body or "")[:MAX_SCAN_LEN]
query_string = (query_string or "")[:MAX_SCAN_LEN]
```

Ini mencegah hang regex pada body besar. Tidak mengubah jumlah fitur.

### 5.4 `core/sidecar_agent.py` (ubah)

Pastikan `SidecarWAF` saat load bundle: (a) memverifikasi `feature_names` bundle
sama persis dengan `FEATURE_NAMES` lokal dan menolak load jika beda, (b) membaca
`block_threshold` dari bundle alih-alih nilai keras. Tidak ada perubahan
protokol TCP 9999 maupun perilaku fail-open.

### 5.5 `tests/test_train_on_real.py` (baru)

Uji invariant, bukan akurasi:
- `X.shape[1] == 33`
- Lima fitur bocor bervarians nol pada dataset tergabung.
- Tidak ada baris duplikat (`subset=[method, uri, query_string, body_truncated]`).
- `attack_types` bundle persis `["XSS", "RCE"]`.
- Tidak ada baris yang sama muncul di train dan test (cek hash baris).

---

## 6. Urutan Tugas untuk Claude Code

1. Pindahkan `merge_datasets.py` ke `tools/`. Jalankan menghasilkan
   `dataset/real/merged_dataset.csv`. Verifikasi laporan: 5.956 baris,
   RCE 3.000 / BENIGN 1.630 / XSS 1.326.
2. Tambahkan pembatas panjang di `features.py` (§5.3). Jalankan tes regresi
   yang ada agar parity 33 fitur tidak rusak.
3. Buat `ml_training/data_loader.py` (§5.1).
4. Buat `ml_training/train_on_real.py` (§5.2), pakai ulang `threshold_sweep`,
   `print_per_attack_recall`, `print_confusion_matrix`, `run_smoke_tests`,
   `_SMOKE_TESTS` dari `train_pipeline.py`. Tambah `report_feature_importance`.
5. Setel `ATTACK_TYPES` yang dipakai pelaporan menjadi `["XSS", "RCE"]`.
6. Latih: `python -m ml_training.train_on_real --csv dataset/real/merged_dataset.csv`.
   Simpan `waf_model.pkl`.
7. Perbarui `core/sidecar_agent.py` untuk parity-check dan baca threshold dari
   bundle (§5.4).
8. Buat `tests/test_train_on_real.py` (§5.5). Jalankan `pytest`.
9. Verifikasi end-to-end: sidecar memuat bundle baru tanpa error parity, smoke
   test lolos.

---

## 7. Kriteria Penerimaan

- `merged_dataset.csv` punya tepat kolom kanonik dan 5.956 baris.
- Pelatihan selesai tanpa error; `X.shape == (5956, 33)`.
- Laporan feature importance menunjukkan `req_rate`, `bot_user_agent`,
  `user_agent_length`, `missing_user_agent`, `missing_host_header` semuanya
  mendekati nol. Jika ada yang tinggi, berarti kebocoran belum tertangani dan
  harus diselidiki sebelum angka dipakai.
- Recall per kelas dilaporkan terpisah untuk XSS dan RCE.
- `pytest` hijau, termasuk uji tanpa-duplikat-antar-split.
- Sidecar memuat bundle baru, parity-check lolos, fail-open tetap berlaku.
- `attack_types` bundle = `["XSS", "RCE"]`. Tidak ada klaim famili lain.

---

## 8. Catatan untuk Thesis

- Bab metodologi harus menyatakan eksplisit: dataset evaluasi hanya mencakup XSS
  dan RCE; benign menjadi minoritas (27,4%) setelah deduplikasi; `class_weight`
  balanced dipakai untuk mengompensasi.
- Sajikan tabel feature importance sebagai bukti model belajar dari payload,
  bukan dari IP atau User-Agent. Ini pertahanan langsung terhadap pertanyaan
  penguji soal validitas akurasi.
- Jelaskan netralisasi kebocoran sebagai keputusan metodologis yang disengaja,
  lengkap dengan alasan mengapa dimensi fitur tetap 33 (kompatibilitas sidecar).
- Untuk angka latency, ukur terpisah lewat timing pada path `SidecarWAF.predict`
  dan smoke test, bukan dari split pelatihan ini.
- Jangan memperluas klaim ke SQLi, path traversal, atau command injection. Jika
  ingin mencakupnya, kumpulkan dulu data nyata dari beberapa IP berbeda memakai
  sqlmap dan ffuf yang sudah ada di tooling, lalu jalankan ulang merge.