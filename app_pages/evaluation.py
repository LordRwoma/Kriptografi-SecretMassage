import hashlib
import os

import pandas as pd
import streamlit as st

import analysis_service as live
from ui_common import HERE, S, fmt, image_key, show_metrics, target_selector


ARCHIVE_TABLES = [
    ("payload_results.csv", "10 ukuran payload"),
    ("robustness.csv", "Ketahanan terhadap serangan"),
    ("capacity.csv", "Kapasitas"),
    ("ml_steganalysis.csv", "Steganalisis ML"),
    ("bruteforce.csv", "Estimasi brute force"),
]


def render():
    st.title("Evaluasi")
    st.caption("Evaluasi ini dihitung dari gambar yang dipilih sekarang. Cover diperlukan untuk metrik kualitas; referensi penyisipan diperlukan untuk BER dan kecocokan payload.")
    target = target_selector("evaluation", with_cover=True)
    if target is not None:
        password = st.text_input(
            "Password untuk evaluasi ekstraksi",
            type="password",
            key="evaluation_password",
            help="Gunakan password yang sama dengan saat menyisipkan payload.",
        )
        st.caption("Isi password, lalu klik **Evaluasi gambar ini**. Menekan Enter saja tidak menjalankan evaluasi.")
        token = (
            image_key(target["stego"]),
            image_key(target["cover"]) if target["cover"] is not None else None,
            hashlib.sha256(password.encode()).hexdigest(),
        )
        if not password:
            st.caption("Isi password untuk mengaktifkan evaluasi.")
        if st.button("Evaluasi gambar ini", type="primary", disabled=not password):
            with st.spinner("Menghitung kualitas, steganalisis, dan ekstraksi..."):
                row = live.evaluate(
                    target["cover"], target["stego"], password,
                    target["expected"], target["info"],
                )
            S["live_evaluation"] = dict(token=token, row=row)
        record = S.get("live_evaluation")
        if record and record["token"] == token:
            row = record["row"]
            (st.success if row["autentikasi_valid"] else st.error)(row["keterangan"])
            show_metrics({
                "PSNR (dB)": fmt(row["PSNR_dB"], 2),
                "SSIM": fmt(row["SSIM"], 5),
                "MSE": fmt(row["MSE"]),
                "BER": fmt(row["BER"]),
            })
            st.dataframe(pd.DataFrame([row]), hide_index=True)
            if target["cover"] is None:
                st.info("PSNR, SSIM, dan MSE memerlukan cover asli. Kolom kosong berarti metrik tidak tersedia.")
            if target["expected"] is None:
                st.info("Payload identik dengan sumber tidak dapat dibandingkan tanpa referensi penyisipan.")

    st.divider()
    st.subheader("Arsip eksperimen historis")
    st.caption("Data di bawah berasal dari eksperimen tersimpan, bukan gambar yang sedang dievaluasi. Eksperimen lama memakai LSB dan tidak mewakili mode DCT/JPEG.")
    result_dir = os.path.join(HERE, "results")
    for filename, title in ARCHIVE_TABLES:
        path = os.path.join(result_dir, filename)
        if not os.path.exists(path):
            continue
        with st.expander(title):
            try:
                st.dataframe(pd.read_csv(path), hide_index=True)
            except (ValueError, OSError) as exc:
                st.error(f"Tabel arsip tidak dapat dibaca: {exc}")

    figures_dir = os.path.join(HERE, "figures")
    if os.path.isdir(figures_dir):
        figures = [name for name in sorted(os.listdir(figures_dir)) if name.lower().endswith(".png")]
        if figures:
            with st.expander("Grafik eksperimen historis"):
                figure = st.selectbox("Pilih grafik arsip", figures)
                st.image(os.path.join(figures_dir, figure), caption=figure, width="stretch")


render()
