# StegoCrypt-X v2 — Kriptografi + Steganografi

## Pembaruan dukungan format dan evaluasi interaktif

- Sampul dan unggahan analisis/ekstraksi menerima PNG, JPG/JPEG, BMP, WebP,
  dan TIFF. Format unggahan dibaca sebagai gambar, bukan berdasarkan ekstensi saja.
- **Hasil PNG:** metode LSB/matrix yang sudah ada, dengan kapasitas besar.
  Sampul JPG dapat dipakai dan hasilnya disimpan sebagai PNG.
- **Hasil JPEG:** metode tambahan DCT-QIM pada luminans blok 8×8, empat
  koefisien per blok, langkah kuantisasi 48, dan ECC 3 wajib (RS 255,127).
  Kualitas simpan 95 dengan subsampling 4:4:4. Ini JPEG asli, bukan PNG yang
  diganti ekstensi atau pesan yang ditaruh di metadata gambar.
- Setiap hasil disimpan, dibaca ulang, dan diekstrak sebelum ditawarkan untuk
  diunduh. Jika verifikasi tidak berhasil, aplikasi menampilkan kesalahan.
- Kapasitas JPEG jauh lebih kecil daripada PNG (873 byte pada
  512×512; angka pasti ditampilkan aplikasi). Gunakan kompresi untuk teks
  atau sampul lebih besar. Gambar yang sangat jenuh/berkontras ekstrem
  mungkin tidak berhasil; gunakan PNG jika verifikasi JPEG ditolak.
- Ekstraksi mendeteksi jalur LSB atau DCT otomatis. PNG lama tetap didukung.
  Mengubah stego LSB lama menjadi JPG tidak memindahkan pesan ke DCT;
  buat ulang penyisipan dengan format hasil JPEG.
- Steganalisis, serangan, dan evaluasi dapat memakai hasil sesi atau gambar
  unggahan. PSNR/SSIM/MSE memerlukan cover asli; BER memerlukan posisi dan
  bit referensi dari penyisipan sesi. Nilai yang tidak tersedia dibiarkan kosong.
- Uji serangan dapat dijalankan satu per satu atau seluruh 16 pengujian;
  hasil tetap terlihat selama sesi dan tabel dapat diunduh sebagai CSV.
  Penghapusan area bawah mempertahankan dimensi gambar.
- Evaluasi gambar pilihan dihitung langsung; tabel/grafik eksperimen lama
  diberi label arsip dan tetap menggambarkan metode LSB, bukan DCT/JPEG.

JPEG tetap tidak dijamin tahan semua kompresi ulang, filter, resize, atau
serangan lain. RS/chi-kuadrat spasial bukan detektor yang memadai untuk
menyimpulkan ketidakterdeteksian metode DCT.

```bash
python cli.py embed --cover foto.jpg --payload rahasia.txt --out stego.jpg --compress
python cli.py extract --stego stego.jpg --out hasil.txt
python cli.py capacity --cover foto.jpg
```

GUI: pilih **Format hasil stego → JPEG** untuk menghasilkan JPG yang dapat
diekstrak. Untuk payload besar, pilih PNG. Ketik password pada tab ekstraksi,
uji serangan, atau evaluasi sebelum menjalankannya.

Modul tambahan: `image_io.py` (baca/simpan), `image_stego.py` (transport
PNG/JPEG dan verifikasi), `analysis_service.py` (evaluasi gambar pilihan),
dan `tests/test_image_workflows.py` (regresi format dan hasil evaluasi).

Dokumentasi dan laporan v2 di bawah merupakan rancangan LSB awal; angka
eksperimennya belum menjadi evaluasi menyeluruh untuk jalur DCT/JPEG baru.

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
