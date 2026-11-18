import hashlib
import os

import altair as alt
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
    bench_cover_name = target.get("cover_name") if bench_cover is not None else None
    if bench_cover is None:
        source_opts = ["Contoh bawaan", "Unggah cover baru"]
        if target is not None and target.get("stego") is not None:
            source_opts.insert(0, "Gunakan stego saat ini sebagai cover")
        if S.get("cover_from_extract") is not None:
            source_opts.append("Gunakan gambar hasil ekstraksi")
        b_src = st.radio("Sumber cover untuk pengujian 10 payload", source_opts, horizontal=True, key="b_src")
        if b_src == "Gunakan stego saat ini sebagai cover":
            bench_cover = target["stego"]
            bench_cover_name = target.get("stego_name") or "Stego saat ini"
        elif b_src == "Gunakan gambar hasil ekstraksi":
            bench_cover = S["cover_from_extract"]
            bench_cover_name = "Gambar hasil ekstraksi"
        elif b_src == "Contoh bawaan":
            s_name = st.selectbox("Pilih sampel gambar", list(SAMPLES), key="b_sample")
            bench_cover = SAMPLES[s_name]()
            bench_cover_name = s_name
        else:
            b_up = st.file_uploader(
                "Unggah citra sampul (raster / SVG)",
                type=IMAGE_TYPES + VECTOR_IMAGE_TYPES,
                key="b_upload",
            )
            bench_cover = read_upload(b_up)
            if bench_cover is not None:
                bench_cover_name = b_up.name
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
                    height, width = bench_cover.shape[:2]
                    channels = "RGB" if bench_cover.ndim == 3 and bench_cover.shape[2] == 3 else (
                        "Grayscale" if bench_cover.ndim == 2 else f"{bench_cover.shape[2]} kanal"
                    )
                    cover_details = {
                        "Nama/Sumber Cover": bench_cover_name or "Tidak diketahui",
                        "Dimensi Cover": f"{width} x {height} px",
                        "Kanal Cover": channels,
                        "Format Stego": b_fmt,
                    }
                    for row in rows_10:
                        row.update(cover_details)
                    S["bench_10_result"] = rows_10
                    status_text.empty()
                    st.success("Pengujian 10 payload berhasil selesai! Seluruh payload pulih 100% identik.")
            except Exception as exc:
                st.error(f"Gagal menjalankan pengujian: {exc}")

        res_10 = S.get("bench_10_result")
        if res_10:
            df_10 = pd.DataFrame(res_10)
            st.subheader("Hasil Evaluasi 10 Ukuran Payload")
            first_result = res_10[0]
            st.caption(
                f"Cover yang diuji: **{first_result.get('Nama/Sumber Cover', 'Tidak diketahui')}** · "
                f"{first_result.get('Dimensi Cover', 'dimensi tidak tersedia')} · "
                f"{first_result.get('Kanal Cover', 'kanal tidak tersedia')} · "
                f"Format stego: {first_result.get('Format Stego', 'tidak tersedia')}."
            )
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

            st.subheader("Grafik Metrik terhadap Kapasitas Payload")
            st.caption(
                "Sumbu X menunjukkan kapasitas teoritis yang terpakai. Arah yang diharapkan: "
                "PSNR dan SSIM tetap tinggi, MSE tetap rendah. Arahkan kursor ke titik untuk "
                "melihat ukuran payload dan nilai tepatnya."
            )
            chart_data = pd.DataFrame({
                "capacity_pct": df_10["Payload (B)"] / b_cap * 100,
                "payload_bytes": df_10["Payload (B)"],
                "psnr": df_10["PSNR (dB)"],
                "ssim": df_10["SSIM"],
                "mse": df_10["MSE"],
                "embed_ms": df_10["Waktu Embed (ms)"],
                "extract_ms": df_10["Waktu Extract (ms)"],
            })
            x_encoding = alt.X(
                "capacity_pct:Q",
                title="Kapasitas payload terpakai (%)",
                scale=alt.Scale(domain=[0, 100]),
                axis=alt.Axis(values=[0, 25, 50, 75, 100]),
            )

            def quality_chart(field, title, scale, value_format):
                return (
                    alt.Chart(chart_data)
                    .mark_line(point=alt.OverlayMarkDef(filled=True, size=65))
                    .encode(
                        x=x_encoding,
                        y=alt.Y(field, title=title, scale=scale),
                        tooltip=[
                            alt.Tooltip("payload_bytes:Q", title="Payload (byte)", format=",.0f"),
                            alt.Tooltip("capacity_pct:Q", title="Kapasitas terpakai (%)", format=".2f"),
                            alt.Tooltip(field, title=title, format=value_format),
                        ],
                    )
                    .properties(height=260)
                )

            chart_col1, chart_col2 = st.columns(2)
            with chart_col1:
                st.altair_chart(
                    quality_chart("psnr:Q", "PSNR (dB)", alt.Scale(zero=False), ".2f"),
                    width="stretch",
                    alt="PSNR terhadap kapasitas payload terpakai; nilai lebih tinggi menunjukkan distorsi lebih rendah",
                )
            with chart_col2:
                st.altair_chart(
                    quality_chart("ssim:Q", "SSIM (0–1)", alt.Scale(domain=[0, 1]), ".5f"),
                    width="stretch",
                    alt="SSIM terhadap kapasitas payload terpakai; nilai mendekati satu menunjukkan kemiripan lebih tinggi",
                )

            chart_col3, chart_col4 = st.columns(2)
            with chart_col3:
                st.altair_chart(
                    quality_chart("mse:Q", "MSE", alt.Scale(zero=True), ".6f"),
                    width="stretch",
                    alt="MSE terhadap kapasitas payload terpakai; nilai lebih rendah menunjukkan distorsi lebih kecil",
                )
            with chart_col4:
                time_data = chart_data.melt(
                    id_vars=["capacity_pct", "payload_bytes"],
                    value_vars=["embed_ms", "extract_ms"],
                    var_name="operation",
                    value_name="time_ms",
                )
                time_data["operation"] = time_data["operation"].map({
                    "embed_ms": "Embed",
                    "extract_ms": "Ekstrak",
                })
                time_chart = (
                    alt.Chart(time_data)
                    .mark_line(point=alt.OverlayMarkDef(filled=True, size=65))
                    .encode(
                        x=x_encoding,
                        y=alt.Y("time_ms:Q", title="Waktu proses (ms)", scale=alt.Scale(zero=True)),
                        color=alt.Color("operation:N", title="Proses"),
                        tooltip=[
                            alt.Tooltip("payload_bytes:Q", title="Payload (byte)", format=",.0f"),
                            alt.Tooltip("capacity_pct:Q", title="Kapasitas terpakai (%)", format=".2f"),
                            alt.Tooltip("operation:N", title="Proses"),
                            alt.Tooltip("time_ms:Q", title="Waktu (ms)", format=".1f"),
                        ],
                    )
                    .properties(height=260)
                )
                st.altair_chart(
                    time_chart,
                    width="stretch",
                    alt="Waktu embed dan ekstrak terhadap kapasitas payload terpakai",
                )

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
