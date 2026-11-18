import os
import time
import zlib

import numpy as np
import pandas as pd
import streamlit as st

import image_stego as transport
import metrics as M
import stegocrypt as sc
from image_io import IMAGE_TYPES, VECTOR_IMAGE_TYPES
from ui_common import (
    ECC_LABEL,
    IMAGE_FORMAT_HELP,
    MODE_LABEL,
    S,
    SAMPLES,
    fmt,
    read_upload,
    safe_filename,
    show_metrics,
)


def render():
    st.title("Sisipkan pesan")
    st.caption("Enkripsi payload lalu sisipkan ke gambar. Hasil unduhan hanya PNG atau JPEG agar metode ekstraksi tetap sesuai.")

    password = st.text_input(
        "Password penyisipan",
        type="password",
        key="insert_password",
        help="Wajib diisi. Password yang sama diperlukan saat ekstraksi.",
    )
    st.caption("Isi password, lalu klik tombol **Enkripsi & sisipkan**. Menekan Enter saja tidak menjalankan penyisipan.")

    format_col, name_col = st.columns(2)
    with format_col:
        output_format = st.selectbox("Format hasil stego", ["PNG", "JPEG"])
    extension = "png" if output_format == "PNG" else "jpg"
    with name_col:
        output_stem = st.text_input(
            "Nama file stego (tanpa ekstensi)",
            value="stego",
            help=f"Ekstensi .{extension} akan ditambahkan otomatis sesuai format hasil.",
        )

    if output_format == "PNG":
        method_col, ecc_col = st.columns(2)
        with method_col:
            mode = st.radio("Metode penyisipan", list(MODE_LABEL), format_func=MODE_LABEL.get)
        with ecc_col:
            ecc = st.selectbox("Koreksi kesalahan (ECC)", list(ECC_LABEL), format_func=ECC_LABEL.get)
        st.caption("PNG menyimpan nilai piksel persis. ECC dapat membantu koreksi sejumlah kerusakan, tetapi tidak membuatnya tahan kompresi lossy.")
    else:
        mode, ecc = "match", 3
        st.info(
            "JPEG memakai DCT-QIM + ECC 3. Pengaturan ini memprioritaskan tampilan dibanding versi sebelumnya; "
            "kompresi ulang, filter, atau resize tetap dapat merusak pesan."
        )

    compress = st.checkbox(
        "Kompres payload sebelum enkripsi",
        help="Kompresi hanya mengurangi ukuran bila isi payload memang dapat dipadatkan.",
    )
    source = st.radio("Citra sampul", ["Contoh bawaan", "Unggah sendiri"], horizontal=True)
    cover = None
    svg_max_edge = 1024
    if source == "Contoh bawaan":
        sample = st.selectbox("Pilih gambar", list(SAMPLES))
        cover = SAMPLES[sample]()
    else:
        cover_upload = st.file_uploader(
            "Unggah sampul raster atau SVG",
            type=IMAGE_TYPES + VECTOR_IMAGE_TYPES,
            key="cover_upload",
            help=IMAGE_FORMAT_HELP,
        )
        if cover_upload and cover_upload.name.lower().endswith(".svg"):
            svg_max_edge = st.selectbox(
                "Resolusi maksimum rasterisasi SVG",
                [512, 1024, 2048],
                index=1,
                help="SVG dirender menjadi piksel sebelum payload disisipkan. Hasil stego tetap PNG/JPEG.",
            )
        cover = read_upload(cover_upload, svg_max_edge=svg_max_edge)

    cap = transport.capacity_bytes(cover.shape, output_format, ecc) if cover is not None else 0
    st.metric(
        "Kapasitas payload tanpa kompresi",
        f"{cap:,} byte",
        help="Perkiraan maksimum payload asli sebelum kompresi; hasil aktual juga bergantung pada ECC.",
    )
    if cover is not None and cap == 0:
        recommendation = (
            "Gunakan sampul lebih besar atau pilih hasil PNG."
            if output_format == "JPEG" else "Gunakan sampul lebih besar."
        )
        st.warning(f"Gambar ini tidak memiliki kapasitas untuk payload {output_format}. {recommendation}")

    payload_kind = st.radio("Sumber payload", ["Teks", "File"], horizontal=True)
    payload_name = "pesan.txt"
    if payload_kind == "Teks":
        payload = st.text_area(
            "Pesan rahasia",
            "Halo! Ini pesan rahasia StegoCrypt-X.",
            height=120,
            help="Teks disimpan sebagai UTF-8, termasuk karakter Unicode dan emoji.",
        ).encode("utf-8")
    else:
        upload = st.file_uploader(
            "File payload (teks, dokumen, gambar, atau file lain)",
            key="payload_upload",
        )
        payload = upload.getvalue() if upload else b""
        if upload:
            payload_name = os.path.basename(upload.name)

    compressed_size = len(zlib.compress(payload, 9)) if compress and payload else len(payload)
    effective_size = min(len(payload), compressed_size) if compress else len(payload)
    st.write(
        f"Ukuran payload: **{len(payload):,} byte** · "
        f"Perkiraan setelah kompresi: **{effective_size:,} byte** · Kapasitas: **{cap:,} byte**"
    )
    st.progress(min(effective_size / max(cap, 1), 1.0))
    over_capacity = effective_size > cap
    if over_capacity:
        advice = (
            "Gunakan sampul lebih besar atau pilih hasil PNG."
            if compress else
            "Aktifkan kompresi, gunakan sampul lebih besar, atau pilih hasil PNG."
        )
        st.warning(f"Payload melebihi kapasitas. {advice}")
    if payload_kind == "File" and not payload:
        st.caption("Pilih file payload yang tidak kosong untuk mengaktifkan penyisipan.")
    elif payload_kind == "Teks" and not payload:
        st.caption("Isi pesan untuk mengaktifkan penyisipan.")
    if not password:
        st.caption("Isi password di atas untuk mengaktifkan tombol penyisipan.")
    if cover is None and source == "Unggah sendiri":
        st.caption("Unggah sampul yang didukung untuk mengaktifkan penyisipan.")

    if st.button(
        "Enkripsi & sisipkan",
        type="primary",
        disabled=cover is None or not payload or not password or over_capacity,
    ):
        try:
            with st.spinner("Menyisipkan dan memverifikasi file hasil..."):
                start = time.perf_counter()
                saved, info, encoded = transport.embed(
                    cover, payload, password, output_format, mode, ecc, compress
                )
                elapsed = (time.perf_counter() - start) * 1000
            S["result"] = dict(
                cover=cover.copy(),
                stego=saved,
                info=info,
                encoded=encoded,
                payload=payload,
                name=payload_name,
                filename=safe_filename(output_stem, extension),
                format=info["output_format"],
                elapsed=elapsed,
            )
            for key in ("extracted", "attack_result", "live_evaluation", "analysis_result"):
                S.pop(key, None)
            st.success("Pesan berhasil disisipkan. File hasil simpan sudah diekstrak ulang dan payload terverifikasi identik.")
        except (ValueError, sc.ExtractionError) as exc:
            st.error(str(exc))

    result = S.get("result")
    if result is None:
        return
    cv, stego, info = result["cover"], result["stego"], result["info"]
    output_filename = result.get(
        "filename",
        safe_filename("stego", "jpg" if result.get("format") == "JPEG" else "png"),
    )
    quality = M.psnr(cv, stego), M.ssim(cv, stego), M.mse(cv, stego)
    st.subheader("Hasil penyisipan terakhir")
    st.caption(f"{result['format']} · {info['mode']} · ECC {info['ecc']} · payload {result['name']}")
    show_metrics({
        "PSNR (dB)": fmt(quality[0], 2),
        "SSIM": fmt(quality[1], 5),
        "MSE": fmt(quality[2]),
        "Waktu + verifikasi": f"{result['elapsed']:.0f} ms",
    })
    st.caption("PSNR/SSIM/MSE membandingkan hasil simpan dengan cover asli. Waktu mencakup penyisipan dan verifikasi ekstraksi setelah file disimpan.")

    changed = np.any(cv != stego, axis=2) if cv.ndim == 3 else cv != stego
    difference = np.zeros((*changed.shape, 3), dtype=np.uint8)
    difference[changed] = (255, 48, 32)
    changed_values = np.abs(cv.astype(np.int16) - stego.astype(np.int16))
    st.caption(
        f"Cover asli dan stego ditampilkan berdampingan. Peta perubahan mewarnai piksel yang berubah "
        f"(merah): {np.count_nonzero(changed):,} piksel; selisih kanal maksimum "
        f"{int(changed_values.max())} dari 255. Warna merah menunjukkan lokasi, bukan ukuran perubahan."
    )
    image_cols = st.columns(3)
    image_cols[0].image(cv, caption="Cover asli", **{"width": "stretch"})
    image_cols[1].image(stego, caption="Stego dari berkas hasil simpan", **{"width": "stretch"})
    image_cols[2].image(difference, caption="Peta lokasi piksel berubah", **{"width": "stretch"})
    mime = "image/jpeg" if result["format"] == "JPEG" else "image/png"
    st.download_button(
        f"Unduh {output_filename}",
        result["encoded"],
        output_filename,
        mime,
        help="Nama file dapat diatur di atas; ekstensi mengikuti format hasil stego.",
    )
    with st.expander("Detail teknis"):
        st.caption("Backend, ECC, dan ukuran blob membantu menelusuri proses penyisipan. Entropi tinggi adalah hal yang diharapkan dari ciphertext.")
        st.json(dict(
            metode=info["mode"],
            backend=info["backend"],
            ecc=info["ecc"],
            kompresi=info["compressed"],
            k_Hamming=info["k"],
            blob_byte=info["blob_len"],
            nilai_kanal_berubah=info["changed"],
            entropi_ciphertext=round(M.entropy_bytes(info["ciphertext"]), 4),
            verifikasi_berkas=info["verified"],
        ))


render()
