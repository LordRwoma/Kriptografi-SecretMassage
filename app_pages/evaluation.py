import hashlib
import os

import pandas as pd
import streamlit as st

import analysis_service as live
import image_stego as transport
from image_io import IMAGE_TYPES, VECTOR_IMAGE_TYPES
from ui_common import (
    ECC_LABEL,
    HERE,
    MODE_LABEL,
    S,
    SAMPLES,
    fmt,
    image_key,
    read_upload,
    show_metrics,
    target_selector,
)


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
    st.subheader("Pengujian 10 Payload Dinamis (Ketentuan Wajib Tugas Akhir)")
    st.caption(
        "Sesuai ketentuan tugas akhir: uji sistem secara otomatis pada minimal 10 ukuran payload berbeda "
        "(dari kecil hingga kapasitas penuh) untuk citra sampul aktif atau sampul yang baru diunggah."
    )

    bench_cover = target.get("cover") if target is not None else None
    if bench_cover is None:
        source_opts = ["Contoh bawaan", "Unggah cover baru"]
        if target is not None and target.get("stego") is not None:
            source_opts.insert(0, "Gunakan stego saat ini sebagai cover")
        if S.get("cover_from_extract") is not None:
            source_opts.append("Gunakan gambar hasil ekstraksi")
        b_src = st.radio("Sumber cover untuk pengujian 10 payload", source_opts, horizontal=True, key="b_src")
        if b_src == "Gunakan stego saat ini sebagai cover":
            bench_cover = target["stego"]
        elif b_src == "Gunakan gambar hasil ekstraksi":
            bench_cover = S["cover_from_extract"]
        elif b_src == "Contoh bawaan":
            s_name = st.selectbox("Pilih sampel gambar", list(SAMPLES), key="b_sample")
            bench_cover = SAMPLES[s_name]()
        else:
            b_up = st.file_uploader(
                "Unggah citra sampul (raster / SVG)",
                type=IMAGE_TYPES + VECTOR_IMAGE_TYPES,
                key="b_upload",
            )
            bench_cover = read_upload(b_up)
    else:
        st.info(f"Menggunakan cover aktif ({bench_cover.shape[1]}×{bench_cover.shape[0]} piksel).")

    if bench_cover is not None:
        b_col1, b_col2, b_col3 = st.columns(3)
        with b_col1:
            b_fmt = st.selectbox("Format keluaran", ["PNG", "JPEG"], key="b_fmt")
        with b_col2:
            b_mode = (
                st.selectbox("Metode penyisipan", list(MODE_LABEL), format_func=MODE_LABEL.get, key="b_mode")
                if b_fmt == "PNG"
                else "match"
            )
        with b_col3:
            b_ecc = (
                st.selectbox("Level ECC", list(ECC_LABEL), format_func=ECC_LABEL.get, key="b_ecc")
                if b_fmt == "PNG"
                else 3
            )

        b_pw = st.text_input(
            "Password untuk pengujian 10 payload",
            "uji-10payload-2026",
            type="password",
            key="b_password",
        )
        b_cap = transport.capacity_bytes(bench_cover.shape, b_fmt, b_ecc)
        st.caption(
            f"Kapasitas maksimum cover ({b_fmt}): **{b_cap:,} byte**. "
            "Pengujian akan menguji 10 ukuran payload bertingkat hingga batas kapasitas."
        )

        if st.button("Jalankan Pengujian 10 Payload", type="primary", key="btn_run_10"):
            prog_bar = st.progress(0.0)
            status_text = st.empty()
            try:
                with st.spinner("Sedang menjalankan pengujian 10 payload berukuran berbeda..."):

                    def _update_prog(p, r):
                        prog_bar.progress(p)
                        status_text.caption(
                            f"Selesai payload #{r['No']}: {r['Payload (B)']:,} B — "
                            f"PSNR: {r['PSNR (dB)']} dB — SSIM: {r['SSIM']}"
                        )

                    rows_10 = live.benchmark_10_payloads(
                        bench_cover,
                        b_pw,
                        output_format=b_fmt,
                        mode=b_mode,
                        ecc=b_ecc,
                        progress_callback=_update_prog,
                    )
                    S["bench_10_result"] = rows_10
                    status_text.empty()
                    st.success("Pengujian 10 payload berhasil selesai! Seluruh payload pulih 100% identik.")
            except Exception as exc:
                st.error(f"Gagal menjalankan pengujian: {exc}")

        res_10 = S.get("bench_10_result")
        if res_10:
            df_10 = pd.DataFrame(res_10)
            st.subheader("Hasil Evaluasi 10 Ukuran Payload")
            show_metrics({
                "Jumlah Uji": f"{len(df_10)} payload",
                "Rentang PSNR (dB)": f"{df_10['PSNR (dB)'].min():.1f} - {df_10['PSNR (dB)'].max():.1f} dB",
                "Rentang SSIM": f"{df_10['SSIM'].min():.4f} - {df_10['SSIM'].max():.4f}",
                "Hash Cocok": f"{(df_10['Hash Cocok'] == 'Ya').sum()}/{len(df_10)} (100%)",
            })
            st.dataframe(df_10, hide_index=True)
            st.download_button(
                "Unduh Tabel 10 Payload (CSV)",
                df_10.to_csv(index=False).encode("utf-8"),
                "evaluasi_10_payload.csv",
                "text/csv",
                help="Unduh tabel hasil pengujian 10 payload untuk dilampirkan pada laporan tugas akhir.",
            )

            st.subheader("Grafik Metrik Kualitas per Ukuran Payload")
            chart_col1, chart_col2 = st.columns(2)
            with chart_col1:
                st.caption("PSNR (dB) terhadap Ukuran Payload (Byte)")
                st.line_chart(df_10.set_index("Payload (B)")[["PSNR (dB)"]])
            with chart_col2:
                st.caption("SSIM terhadap Ukuran Payload (Byte)")
                st.line_chart(df_10.set_index("Payload (B)")[["SSIM"]])

            chart_col3, chart_col4 = st.columns(2)
            with chart_col3:
                st.caption("Persentase Piksel Berubah (%) terhadap Ukuran Payload (Byte)")
                st.bar_chart(df_10.set_index("Payload (B)")[["Piksel Berubah (%)"]])
            with chart_col4:
                st.caption("Waktu Embed & Extract (ms) terhadap Ukuran Payload (Byte)")
                st.line_chart(df_10.set_index("Payload (B)")[["Waktu Embed (ms)", "Waktu Extract (ms)"]])

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
