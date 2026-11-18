# Robustness dan Complexity & Efisiensi

Fitur ini menambah **evaluasi**; algoritma inti AES-GCM, LSB/matrix,
Reed–Solomon, serta transport JPEG tidak diganti. Kegagalan setelah gangguan
tetap dicatat sebagai hasil eksperimen, bukan dibuat seolah-olah berhasil.

## Uji robustness di aplikasi

1. Buat hasil di **Sisipkan**, kemudian buka **Uji serangan**. Unggahan stego
   juga dapat dipakai, tetapi tidak memiliki bit referensi body dari sesi.
2. Masukkan password yang benar, pilih kelompok dan tingkat gangguan.
3. Pilih satu serangan atau seluruh serangan dalam kelompok/tingkat pilihan.
4. Tekan **Jalankan uji serangan**. Kontrol tanpa serangan diperiksa dahulu;
   jika kontrol gagal, pengujian dibatalkan.
5. Lihat tabel dan grafik, pilih pratinjau hasil, unduh gambar atau CSV.

Tingkat ringan/sedang/berat menyatakan besar gangguan dalam keluarga serangan.
Tingkat tersebut tidak mengasumsikan metode LSB dapat menahannya dan bukan
skala universal yang menyamakan JPEG, noise, dan cropping.

Serangan meliputi JPEG kualitas 95–10, Gaussian noise sigma 1–10,
salt-and-pepper 0,05–5% per nilai kanal, median/Gaussian/average filtering,
sharpening, penghapusan area, cropping dimensi, resize 90/75/50/25% dengan
nearest/bilinear/bicubic (dengan atau tanpa kembali ke dimensi awal), rotasi,
pergeseran, dan dua rangkaian serangan gabungan. Seed gangguan tercatat pada
parameter agar setiap serangan dapat direproduksi. Skenario noise ini memakai
satu seed tetap; bukan estimasi statistik keberhasilan atas banyak seed.

### Pembacaan hasil

- **Autentikasi valid:** AES-GCM menerima hasil pemulihan.
- **Payload identik:** byte hasil sama dengan payload referensi, jika tersedia.
- **BER:** bit body pada posisi penyisipan referensi sebelum ECC dibandingkan
  dengan bit asli. Bukan BER plaintext. Untuk matrix, yang dibandingkan adalah
  bit hasil pembacaan syndrome; untuk DCT, bit dari carrier koefisien.
- **PSNR/SSIM/MSE:** stego sebelum serangan dibandingkan stego setelah serangan,
  pada koordinat yang sama. Rotasi/geser dengan dimensi tetap tetap menghitung
  metrik koordinat tersebut, bukan kemiripan setelah registrasi.
- Jika dimensi berubah, BER dan metrik kualitas tidak dihitung. Tidak ada
  resize otomatis untuk menyamakan pembanding. Ekstraksi tetap dicoba.
- **Waktu ekstraksi:** pemulihan dan pemeriksaan identitas; **waktu total uji**
  juga mencakup gangguan dan perhitungan metrik. Keduanya bukan benchmark murni
  tahap penyisipan; gunakan halaman efisiensi.

Cropping tengah mengurangi **lebar dan tinggi** sesuai persentase. Contoh
potong 25% tiap dimensi menyisakan sekitar 56,25% luas, bukan 75% luas.
Penghapusan area tengah/acak mempertahankan dimensi dan membentuk persegi
panjang dengan luas mendekati persentase yang dipilih (pembulatan piksel).

Daftar `attacks.SUITE` tetap berisi 16 serangan lama untuk menjaga kompatibilitas
skrip arsip `evaluate.py`. GUI memakai daftar lengkap `attacks.ATTACK_SUITE`
beserta parameter di `attacks.DETAILS`.

## Benchmark waktu dan memori

1. Buka **Complexity & Efisiensi** di sidebar.
2. Pilih contoh cover, cover penyisipan terakhir, atau unggah cover.
3. Pilih PNG/JPEG, mode dan ECC yang sesuai. JPEG selalu memakai ECC 3.
4. Pilih resolusi asli atau sisi terpanjang 512/1024/2048. Rasio aspek dijaga;
   dimensi kanal minimum 8 piksel. Pilihan dengan dimensi identik dihitung sekali.
5. Gunakan **10 ukuran, byte sama di semua resolusi** untuk mengontrol ukuran
   payload ketika mempelajari perubahan resolusi. Alternatifnya gunakan 10
   ukuran relatif terhadap kapasitas tiap cover atau ukuran manual.
6. Biarkan kompresi nonaktif untuk percobaan ukuran payload awal. Payload berupa
   byte pseudoacak dengan seed yang dapat diatur. Salt/nonce tetap acak.
7. Masukkan password dan jalankan. Default lima pengulangan, satu pemanasan per
   skenario. Percobaan besar dapat memerlukan beberapa menit.
8. Unduh ringkasan CSV atau ZIP berisi data mentah, ringkasan, metadata dan grafik
   PNG. Password, kunci dan isi payload tidak disertakan dalam ekspor.

### Definisi pengukuran

Setiap pasangan resolusi–ukuran payload dijalankan dalam **proses Python baru**
tanpa Streamlit. Pembuatan payload, impor pustaka, startup proses, pengubahan
resolusi cover, dan pemanasan tidak masuk waktu tahap yang diukur.

PNG memisahkan penyisipan inti, encoding PNG, pembacaan PNG, ekstraksi dan cek
identik, serta total alur. Ekstraksi dilakukan pada gambar yang benar-benar
disimpan menjadi byte PNG dan dibaca ulang. Encoding/pembacaan dilakukan di
memori: hasil ini tidak mengukur kecepatan disk atau jaringan.

JPEG memakai `image_stego.embed` aktual yang menyertakan penyimpanan,
pembacaan ulang, verifikasi serta hingga empat percobaan internal. Tahap ini
diberi nama **Sisip-simpan-verifikasi JPEG**, bukan waktu penyisipan murni.
Ekstraksi setelah tahap tersebut merupakan pengukuran tambahan dengan backend
DCT yang sudah diketahui, tanpa biaya deteksi otomatis metode.

Waktu diukur memakai `time.perf_counter()`. Memori diukur pada lintasan lain
agar thread sampling tidak masuk angka waktu benchmark. Karena salt/nonce
tetap acak, kedua lintasan bukan operasi identik; keduanya wajib memulihkan
payload. Median/minimum/maksimum/simpangan baku populasi waktu tersedia di tabel.

Memori adalah RSS/working set melalui `psutil`, termasuk alokasi native seperti
scrypt. Sampling setiap 2 ms, ditambah sampel batas tahap, menghasilkan
**puncak teramati**, bukan jaminan puncak mutlak. Tabel menyajikan baseline,
puncak absolut dan kenaikan terhadap baseline. Baseline diambil setelah
pemanasan; pustaka/allocator bisa mempertahankan alokasi antar pengulangan.
Kenaikan RSS nol tidak berarti kebutuhan memori nol. Jangan menjumlahkan puncak
tiap tahap: masing-masing memiliki baseline berbeda.

Skenario gagal/timeout dicatat terpisah dan tidak dianggap hasil berhasil.
Lingkungan perangkat, versi pustaka, seed, pengaturan aktual, hash cover dan
hash payload disimpan agar hasil dapat ditelusuri. Hasil penyisipan sesi tidak
ditimpa oleh benchmark.

## Complexity analitis

Untuk N nilai kanal carrier, B byte blob dan m posisi body, `_keyed_order`
membuat stream PRF berukuran O(N), menyeleksi subset dan mengurutkan m nilai
(O(m log m)); jika m mencapai N, cabang kode memakai pengurutan seluruh carrier.
Gunakan batas konservatif **O(N log N + B)** waktu dan **O(N + B + K)** ruang
untuk inti jalur berkunci dengan K memori scrypt pada parameter tetap.
Matrix k dibatasi 12; ukuran blok Reed–Solomon dan jumlah percobaan JPEG juga
dibatasi. DCT 8×8 menambah kerja linear terhadap jumlah piksel. Kompresi dan
codec menambah biaya tersendiri. Grafik benchmark adalah observasi perangkat,
bukan bukti Big-O. Perbandingan format/ECC harus menyebut metode aktualnya.
