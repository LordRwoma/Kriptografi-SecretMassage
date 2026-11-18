import pandas as pd
import numpy as np
import streamlit as st

import analysis_service as live
from ui_common import S, fmt, image_key, show_metrics, target_selector


def render():
    st.title("Steganalisis")
    st.caption("Lihat indikator statistik gambar. Metrik ini tidak membuktikan pesan pasti ada atau tidak ada.")
    target = target_selector("analysis", with_cover=True)
    if target is None:
        return
    stego, cover = target["stego"], target["cover"]
    token = (image_key(stego), image_key(cover) if cover is not None else None)

    if st.button("Jalankan steganalisis", type="primary"):
        with st.spinner("Menghitung metrik gambar..."):
            S["analysis_result"] = dict(
                token=token,
                stego=live.steganalysis(stego),
                cover=live.steganalysis(cover) if cover is not None else None,
                quality=live.quality(cover, stego),
            )
    record = S.get("analysis_result")
    if not record or record["token"] != token:
        return

    frame = pd.DataFrame([record["stego"]], index=["Stego"])
    if record["cover"] is not None:
        frame.loc["Cover"] = record["cover"]
    st.dataframe(frame, hide_index=False)
    quality = record["quality"]
    show_metrics({
        "PSNR (dB)": fmt(quality["PSNR_dB"], 2),
        "SSIM": fmt(quality["SSIM"], 5),
        "MSE": fmt(quality["MSE"]),
    })
    histogram = {"Stego": np.bincount(stego.ravel(), minlength=256)}
    if cover is not None:
        histogram["Cover"] = np.bincount(cover.ravel(), minlength=256)
    st.subheader("Histogram nilai kanal")
    st.caption("Membandingkan sebaran intensitas 0–255. Perubahan kecil atau tidak terlihat pada histogram bukan bukti bahwa pesan tidak ada.")
    st.line_chart(pd.DataFrame(histogram))
    left, right = st.columns(2)
    left.image(stego, caption="Gambar yang dianalisis", width="stretch")
    if stego.ndim == 3:
        right.image((stego[..., 1] & 1) * 255, caption="Bidang LSB kanal hijau", width="stretch")
    else:
        right.info("Visualisasi LSB kanal hijau hanya berlaku untuk gambar RGB.")
    st.caption("RS dan chi-kuadrat adalah indikator statistik, bukan bukti ada/tidaknya pesan. Metode JPEG/DCT memerlukan analisis frekuensi khusus; metrik spasial LSB tidak cukup untuk menyimpulkan ketidakterdeteksian.")
    if cover is None:
        st.info("Unggah cover asli untuk menampilkan PSNR, SSIM, dan MSE.")


render()
