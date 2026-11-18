import streamlit as st


def render():
    result = st.session_state.get("result")
    st.title("Beranda StegoCrypt-X")
    st.caption(
        "Kenali aplikasi dan ikuti panduan singkat untuk mengenkripsi pesan, "
        "menyisipkannya ke gambar, lalu menguji hasilnya."
    )

    st.info(
        "StegoCrypt-X mengenkripsi teks atau file dengan password, lalu "
        "menyisipkan data terenkripsi ke dalam gambar. Hasilnya berupa gambar "
        "PNG atau JPEG yang dapat diunduh."
    )

    if result:
        info = result.get("info", {})
        status = "Terverifikasi" if info.get("verified") else "Perlu diperiksa"
        image_format = result.get("format", "—")
        payload_size = f"{len(result.get('payload', b'')):,} byte"
    else:
        status = "Belum ada hasil"
        image_format = "—"
        payload_size = "—"

    with st.container(horizontal=True):
        st.metric("Status sesi", status, border=True)
        st.metric("Format hasil terakhir", image_format, border=True)
        st.metric("Ukuran payload terakhir", payload_size, border=True)

    st.page_link(
        "app_pages/insert.py",
        label="Mulai sisipkan pesan",
        icon=":material/lock:",
        width="content",
    )

    st.header("Cara menggunakan")
    st.markdown(
        """
1. Buka **Sisipkan**, pilih gambar sampul atau unggah gambar sendiri.
2. Tentukan format hasil, masukkan password, lalu pilih teks atau file yang akan disisipkan.
3. Tekan **Enkripsi & sisipkan**. Aplikasi menyimpan hasil dan memeriksa apakah payload dapat diekstrak kembali.
4. Unduh gambar stego. Untuk mengambil payload, buka **Ekstrak**, gunakan gambar tersebut dan password yang sama.
5. Jika diperlukan, buka **Steganalisis**, **Uji serangan**, atau **Evaluasi** untuk memeriksa karakteristik dan ketahanan hasil.
6. Buka **Complexity & Efisiensi** untuk mengukur waktu dan memori pada beberapa ukuran payload dan resolusi.
"""
    )

    st.header("Fitur utama")
    feature_rows = (
        (
            ("Sisipkan", "Enkripsi dan sisipkan teks atau file. PNG menyediakan pilihan metode dan ECC; JPEG memakai DCT-QIM."),
            ("Ekstrak", "Pulihkan payload dari gambar stego menggunakan password yang benar."),
            ("Steganalisis", "Periksa indikator statistik gambar. Hasil analisis bukan bukti pasti bahwa gambar berisi atau tidak berisi pesan."),
        ),
        (
            ("Uji serangan", "Amati apakah payload masih dapat dipulihkan setelah gambar mengalami perubahan. Serangan memang dapat merusak pesan."),
            ("Evaluasi", "Lihat metrik kualitas jika cover tersedia dan bandingkan hasil sesi dengan arsip eksperimen."),
            ("Complexity & Efisiensi", "Ukur waktu dan memori di proses terpisah, lalu unduh tabel dan grafik benchmark."),
        ),
    )
    page_paths = {
        "Sisipkan": "app_pages/insert.py",
        "Ekstrak": "app_pages/extract.py",
        "Steganalisis": "app_pages/analysis.py",
        "Uji serangan": "app_pages/attacks.py",
        "Evaluasi": "app_pages/evaluation.py",
        "Complexity & Efisiensi": "app_pages/benchmark.py",
    }
    for row in feature_rows:
        columns = st.columns(len(row))
        for column, (title, description) in zip(columns, row):
            with column:
                with st.container(border=True):
                    st.subheader(title)
                    st.write(description)
                    st.page_link(page_paths[title], label=f"Buka {title}")

    st.warning(
        "⚠️ **Panduan Penting Penggunaan & Pengiriman Stego:**\n\n"
        "- **Kirim sebagai Dokumen (Bukan Foto Galeri)**: Aplikasi pesan instan (seperti WhatsApp, Telegram, atau Instagram) "
        "selalu mengompresi gambar yang dikirim sebagai foto/media biasa, sehingga bit-bit steganografi akan rusak total. "
        "Selalu kirimkan file stego sebagai **Dokumen / Berkas Asli** tanpa kompresi.\n"
        "- **Hindari Resize & Cropping Nyata**: Mengubah resolusi (lebar/tinggi) atau memotong gambar akan "
        "mengacaukan permutasi acak berkunci penyisipan.\n"
        "- **Password**: Gunakan password yang sama persis saat menyisipkan dan mengekstrak pesan."
    )


render()
