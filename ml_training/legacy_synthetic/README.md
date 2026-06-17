# legacy_synthetic — kode dataset SINTETIS (diarsipkan, tidak dipakai)

Berisi pipeline data **sintetis** lama yang sudah **tidak digunakan**. Model WAF
sekarang dilatih dari **data real** di `ml_training/data_train/labeled/` lewat
`ml_training/train_on_real.py`.

Isi:
- `dataset_generator.py` — generator dataset sintetis OJS.
- `train_pipeline.py` — pipeline training berbasis sintetis (atau `merge.csv`).
- `train_waf_model.py` — trainer sintetis paling lama (`generate_synthetic_dataset()`).
- `merge.csv` — dataset gabungan skema-lama (sengaja DIKECUALIKAN oleh `data_loader`).

Helper bersama yang dulu ada di `train_pipeline.py`
(`build_feature_matrix`, `print_confusion_matrix`, `print_per_attack_recall`,
`threshold_sweep`) sudah dipindah ke `ml_training/training_utils.py` dan dipakai
jalur real.

Catatan: file di sini diarsipkan apa adanya. Path/`PROJECT_DIR` sudah disesuaikan
seperlunya, tapi tidak dijamin jalan 100% — tujuannya sebagai referensi, bukan
bagian alur training aktif.
