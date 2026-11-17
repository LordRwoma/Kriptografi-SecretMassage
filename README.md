# StegoCrypt-X v2 — Kriptografi + Steganografi

Tugas Akhir **Kriptografi & Keamanan Data**. Kombinasi **tepat 2 metode**: **Kriptografi** (AES-256-GCM, scrypt, HKDF) + **Steganografi** (LSB matching + matrix embedding, posisi acak berkunci) pada media **citra**.

## Alur sistem
```
PENGIRIM  password ─scrypt→ master ─HKDF→ [kunci AES-256 | kunci PRF posisi | mask header]
          payload ─(zlib)→ AES-256-GCM(AAD=header) ─(Reed-Solomon)→ blob
          blob ─ Hamming matrix embedding + LSB matching ±1 @ posisi acak berkunci → stego.png
PENERIMA  stego.png → header 256 bit (salt|nonce|ctrl⊕mask) → kunci → baca LSB → decode → RS → tag GCM → payload
```
Keputusan desain: tanpa *magic number* (seluruh aliran tampak acak); panjang & flag di-mask; salt & nonce acak per pesan; tag GCM
mengautentikasi header + data (deteksi tamper); posisi dari PRF **AES-256-CTR** (stabil lintas versi NumPy); **matrix embedding**
menurunkan jumlah piksel berubah hingga ±5×; **Reed-Solomon opsional** (ECC 1–3) untuk ketahanan noise/cropping ringan.

## Instalasi & menjalankan
```bash
pip install -r requirements.txt
python cli.py demo                                   # demo terminal end-to-end (±10 dtk)
streamlit run app.py                                 # demo GUI interaktif (disarankan untuk presentasi)
python cli.py embed   --cover foto.png --payload rahasia.txt --out stego.png --ecc 0 --compress
python cli.py extract --stego stego.png --out hasil.txt
python cli.py capacity --cover foto.png
python cli.py analyze --cover foto.png --stego stego.png
python -m unittest discover -s tests -v              # 18 unit test
python evaluate.py                                   # seluruh eksperimen (± 8 menit) → results/*.csv, figures/*.png
```
Password dibaca dari prompt (`getpass`) atau env `STEGO_PASSWORD` bila `--password` tidak diberikan. Simpan stego sebagai **PNG** (lossless).

## Struktur
| Berkas | Isi |
|---|---|
| `stegocrypt.py` | inti: kripto, ECC, matrix embedding, embed/extract |
| `metrics.py` | PSNR/SSIM/MSE/BER, entropi, uji keacakan (monobit/runs/χ²), RS, χ² Westfeld, fitur SPAM + detektor ML |
| `attacks.py` | 16 serangan robustness (JPEG, noise, S&P, filter, cropping, resize) |
| `steganalysis.py` | eksperimen ablasi 4 skema + detektor ML *leave-one-cover-out* |
| `evaluate.py` | seluruh eksperimen → `results/`, `figures/` |
| `cli.py`, `app.py` | demo terminal & GUI Streamlit |
| `tests/` | 18 unit test |
| `docs/` | laporan & slide |

## Batasan yang diakui
LSB bersifat rapuh terhadap kompresi lossy/filter (lihat Bab Robustness); ECC hanya menolong noise impuls & cropping ringan. Cropping nyata
(dimensi berubah) tidak didukung karena pemetaan posisi bergantung ukuran citra. Memori yang diukur adalah alokasi Python/NumPy (`tracemalloc`);
scrypt (32 MiB) dialokasikan di sisi C sehingga tidak terhitung.
