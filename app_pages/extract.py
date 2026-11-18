import hashlib

import streamlit as st

import image_stego as transport
import stegocrypt as sc
from ui_common import S, safe_payload_filename, target_selector


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
    try:
        preview = output.decode("utf-8")
        st.text_area("Pratinjau teks (maksimal 4.000 karakter)", preview[:4000], height=150)
        if len(preview) > 4000:
            st.caption("Pratinjau diringkas; unduhan berisi seluruh payload.")
    except UnicodeDecodeError:
        st.info("Payload biner. Unduh hasil untuk membuka file aslinya.")

    default_name = "hasil_ekstraksi.bin"
    if target["expected"] is not None and S.get("result") is not None:
        default_name = S.result["name"]
    filename = st.text_input(
        "Nama file hasil ekstraksi",
        default_name,
        key=f"extract_filename_{token[0][:12]}",
        help="Untuk gambar yang diunggah, nama/ekstensi payload tidak tersimpan di dalam gambar; tentukan nama file yang sesuai.",
    )
    st.download_button(
        "Unduh hasil ekstraksi",
        output,
        safe_payload_filename(filename),
        "application/octet-stream",
    )


render()
