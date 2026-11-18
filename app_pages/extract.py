import hashlib
import io
import numpy as np
import streamlit as st

import image_stego as transport
import metrics as M
import stegocrypt as sc
from ui_common import S, safe_payload_filename, target_selector


def _guess_extension(data: bytes) -> str:
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"BM"):
        return "bmp"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return "webp"
    try:
        data.decode("utf-8")
        return "txt"
    except UnicodeDecodeError:
        return "bin"


def render():
    st.title("Ekstrak pesan")
    st.caption("Gunakan gambar stego asli dan password yang dipakai saat penyisipan.")
    target = target_selector("extract")
    if target is None:
        return

    password = st.text_input(
        "Password ekstraksi",
        type="password",
        key="extract_password",
        help="Harus sama dengan password penyisipan.",
    )
    st.caption("Isi password, lalu klik **Ekstrak & dekripsi**. Menekan Enter saja tidak menjalankan ekstraksi.")
    token = (hashlib.sha256(target["stego"].tobytes()).hexdigest(),
             hashlib.sha256(password.encode()).hexdigest())
    if not password:
        st.caption("Isi password untuk mengaktifkan tombol ekstraksi.")
    if st.button("Ekstrak & dekripsi", type="primary", disabled=not password):
        S.pop("extracted", None)
        try:
            with st.spinner("Mengekstrak dan memverifikasi pesan..."):
                output = transport.extract(target["stego"], password)
            S["extracted"] = dict(
                token=token,
                data=output,
                identical=output == target["expected"] if target["expected"] is not None else None,
            )
        except sc.ExtractionError as exc:
            st.error(str(exc))

    record = S.get("extracted")
    if not record or record["token"] != token:
        return
    output = record["data"]
    st.success(f"Berhasil mengekstrak {len(output):,} byte. Autentikasi GCM valid.")
    if record["identical"] is not None:
        st.write("Identik dengan payload asli:", "Ya" if record["identical"] else "Tidak")
    st.code(f"SHA-256: {hashlib.sha256(output).hexdigest()}")
    # Check if the extracted data is an image
    is_image = False
    try:
        from PIL import Image as PILImage
        img_stream = io.BytesIO(output)
        pil_img = PILImage.open(img_stream)
        pil_img.load()
        is_image = True
    except Exception:
        is_image = False

    if is_image:
        st.subheader("Pratinjau Citra Hasil Ekstraksi")
        st.image(output, caption=f"Gambar terekstrak: {pil_img.size[0]}×{pil_img.size[1]} piksel, mode {pil_img.mode}")
        act_col1, act_col2 = st.columns(2)
        with act_col1:
            if st.button("Gunakan gambar ini sebagai cover baru untuk penyisipan", key="btn_use_as_cover"):
                S["cover_from_extract"] = np.array(pil_img.convert("RGB"))
                st.success("Gambar berhasil disimpan! Anda dapat memilihnya di halaman Sisipkan.")
        with act_col2:
            if st.button("Kirim gambar ini ke halaman Steganalisis", key="btn_send_to_steganalysis"):
                S["stego_from_extract"] = np.array(pil_img.convert("RGB"))
                st.info("Gambar siap dianalisis di halaman Steganalisis.")

    # Audio preview if audio
    if (output.startswith(b"RIFF") and len(output) > 12 and output[8:12] == b"WAVE") or output.startswith(b"ID3") or output.startswith(b"\xff\xfb"):
        st.subheader("Pratinjau Audio Hasil Ekstraksi")
        st.audio(output)

    try:
        preview = output.decode("utf-8")
        st.text_area("Pratinjau teks (maksimal 4.000 karakter)", preview[:4000], height=150)
        if len(preview) > 4000:
            st.caption("Pratinjau diringkas; unduhan berisi seluruh payload.")
    except UnicodeDecodeError:
        if not is_image:
            st.info("Payload biner. Unduh hasil untuk membuka file aslinya.")

    default_name = "hasil_ekstraksi.bin"
    guessed_ext = _guess_extension(output)
    if target["expected"] is not None and S.get("result") is not None:
        default_name = S.result["name"]
    else:
        default_name = f"hasil_ekstraksi.{guessed_ext}"
        if guessed_ext != "bin":
            st.info(f"💡 Format file terdeteksi: **.{guessed_ext}**. Nama default telah disesuaikan.")
    filename = st.text_input(
        "Nama file hasil ekstraksi",
        default_name,
        key=f"extract_filename_{token[0][:12]}",
        help="Untuk gambar yang diunggah, nama/ekstensi payload tidak tersimpan di dalam gambar; tentukan nama file yang sesuai.",
    )
    st.caption("Tips: Jika berkas asli adalah dokumen/media tertentu, pastikan ekstensi nama file di atas sesuai sebelum mengunduh.")
    st.download_button(
        "Unduh hasil ekstraksi",
        output,
        safe_payload_filename(filename),
        "application/octet-stream",
    )

    with st.expander("Detail Analisis & Integritas Payload (Nilai Tambah)"):
        st.caption("Metrik keamanan payload terenkripsi dan hasil pemulihan data.")
        st.json({
            "Ukuran (Byte)": len(output),
            "Ukuran (KiB)": round(len(output) / 1024, 2),
            "SHA-256": hashlib.sha256(output).hexdigest(),
            "MD5": hashlib.md5(output).hexdigest(),
            "Entropi Shannon": round(M.entropy_bytes(output), 4),
            "Format Terdeteksi": guessed_ext,
            "Autentikasi GCM": "Valid (Integritas Terjamin)",
        })


render()
