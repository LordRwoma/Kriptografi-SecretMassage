"""StegoCrypt-X: run with streamlit run app.py."""
import hashlib
import os
import time
import numpy as np
import pandas as pd
import streamlit as st
from skimage import data as skdata

import analysis_service as live
import attacks as A
import image_stego as transport
import metrics as M
import stegocrypt as sc
from image_io import IMAGE_TYPES, encode_image, load_image

st.set_page_config(page_title="StegoCrypt-X", page_icon="🔐", layout="wide")
_version = tuple(int(x) for x in st.__version__.split(".")[:2])
FIT = {"width": "stretch"} if _version >= (1, 50) else {"use_container_width": True}
HERE = os.path.dirname(os.path.abspath(__file__))
S = st.session_state
SAMPLES = {"astronaut (512 × 512)": skdata.astronaut, "coffee (400 × 600)": skdata.coffee,
           "chelsea (300 × 451)": skdata.chelsea, "rocket (427 × 640)": skdata.rocket,
           "immunohistochemistry (512 × 512)": skdata.immunohistochemistry}
MODE_LABEL = {"matrix": "Matrix embedding + LSB matching", "match": "LSB matching ±1", "replace": "LSB replacement"}
ECC_LABEL = {0: "Tanpa ECC", 1: "ECC 1 — RS(255,223)", 2: "ECC 2 — RS(255,191)", 3: "ECC 3 — RS(255,127)"}


def read_upload(upload):
    if upload is None:
        return None
    try:
        image = load_image(upload)
        if min(image.shape[:2]) < 8:
            raise ValueError("Gunakan gambar minimal 8 × 8 piksel.")
        return image
    except ValueError as exc:
        st.error(str(exc))
        return None


def image_key(image):
    return hashlib.sha256(str(image.shape).encode() + image.tobytes()).hexdigest()


def show_metrics(values):
    for col, (label, val) in zip(st.columns(len(values)), values.items()):
        col.metric(label, "—" if val is None else val)


def fmt(value, digits=4):
    if value is None:
        return "—"
    return "∞" if np.isinf(value) else f"{value:.{digits}f}"


def csv_download(frame, name, key):
    st.download_button("Unduh tabel CSV", frame.to_csv(index=False).encode("utf-8-sig"),
                       name, "text/csv", key=key)


def target_selector(key, with_cover=False):
    source = st.radio("Sumber gambar", ["Hasil penyisipan terakhir", "Unggah gambar"], horizontal=True, key=f"{key}_source")
    if source == "Hasil penyisipan terakhir":
        result = S.get("result")
        if result is None:
            st.info("Sisipkan pesan terlebih dahulu atau pilih unggah gambar.")
            return None
        st.caption(f"Hasil tersimpan: {result['format']} · {result['name']} · {len(result['payload']):,} byte payload")
        return dict(stego=result["stego"], cover=result["cover"], expected=result["payload"], info=result["info"])
    upload = st.file_uploader("Gambar stego (PNG/JPG/JPEG/BMP/WebP/TIFF)", type=IMAGE_TYPES, key=f"{key}_stego")
    image = read_upload(upload)
    cover = None
    if with_cover:
        cover = read_upload(st.file_uploader("Cover asli untuk perbandingan kualitas (opsional)", type=IMAGE_TYPES, key=f"{key}_cover"))
        if cover is not None and image is not None and cover.shape != image.shape:
            st.error("Dimensi cover dan stego berbeda. Unggah pasangan dengan dimensi yang sama.")
            return None
    return None if image is None else dict(stego=image, cover=cover, expected=None, info=None)


st.title("🔐 StegoCrypt-X")
st.caption("Enkripsi AES-256-GCM dan steganografi citra · PNG: LSB/matrix · JPEG: DCT-QIM + ECC")
with st.sidebar:
    st.header("Pengaturan penyisipan")
    password = st.text_input("Password penyisipan", type="password")
    output_format = st.selectbox("Format hasil stego", ["PNG", "JPEG"])
    if output_format == "PNG":
        mode = st.radio("Metode penyisipan", list(MODE_LABEL), format_func=MODE_LABEL.get)
        ecc = st.selectbox("Koreksi kesalahan", list(ECC_LABEL), format_func=ECC_LABEL.get)
        st.caption("Sampul JPG dapat digunakan. Hasil PNG menjaga bit LSB setelah disimpan.")
    else:
        mode, ecc = "match", 3
        st.info("JPEG memakai DCT-QIM + ECC 3, kualitas 95. Kapasitas lebih kecil. Kompresi ulang tetap dapat merusak pesan.")
    compress = st.checkbox("Kompres payload sebelum enkripsi")
    src = st.radio("Citra sampul", ["Contoh bawaan", "Unggah sendiri"])
    if src == "Contoh bawaan":
        cover = SAMPLES[st.selectbox("Pilih gambar", list(SAMPLES))]()
    else:
        cover = read_upload(st.file_uploader("Unggah sampul PNG/JPG/JPEG/BMP/WebP/TIFF", type=IMAGE_TYPES, key="cover_upload"))
    cap = transport.capacity_bytes(cover.shape, output_format, ecc) if cover is not None else 0
    st.metric("Kapasitas payload tanpa kompresi", f"{cap:,} byte")
    st.caption("Kapasitas sesuai format hasil dan ECC. Kompresi hanya membantu data yang dapat dipadatkan.")

tabs = st.tabs(["Sisipkan", "Ekstrak", "Steganalisis", "Uji serangan", "Hasil evaluasi"])
with tabs[0]:
    kind = st.radio("Sumber payload", ["Teks", "File"], horizontal=True)
    payload_name = "pesan.txt"
    if kind == "Teks":
        payload = st.text_area("Pesan rahasia", "Halo! Ini pesan rahasia StegoCrypt-X.", height=120).encode("utf-8")
    else:
        upload = st.file_uploader("File payload (teks, dokumen, gambar, atau file lain)", key="payload_upload")
        payload = upload.getvalue() if upload else b""
        if upload:
            payload_name = os.path.basename(upload.name)
    st.write(f"Ukuran payload: **{len(payload):,} byte** · Kapasitas: **{cap:,} byte**")
    st.progress(min(len(payload) / max(cap, 1), 1.0))
    if len(payload) > cap:
        st.info("Payload melebihi kapasitas tanpa kompresi. Aktifkan kompresi atau gunakan gambar lebih besar/format PNG.")
    if st.button("Enkripsi & sisipkan", type="primary", disabled=cover is None or not payload or not password):
        try:
            with st.spinner("Menyisipkan dan memverifikasi hasil penyimpanan..."):
                start = time.perf_counter()
                saved, info, encoded = transport.embed(cover, payload, password, output_format, mode, ecc, compress)
                elapsed = (time.perf_counter() - start) * 1000
            S["result"] = dict(cover=cover.copy(), stego=saved, info=info, encoded=encoded,
                               payload=payload, name=payload_name, format=info["output_format"], elapsed=elapsed)
            for key in ("extracted", "attack_result", "live_evaluation"):
                S.pop(key, None)
            st.success("Pesan berhasil disisipkan. Ekstraksi dari berkas hasil simpan sudah diverifikasi identik.")
        except (ValueError, sc.ExtractionError) as exc:
            st.error(str(exc))
    if "result" in S:
        result = S.result
        cv, sg, info = result["cover"], result["stego"], result["info"]
        q = live.quality(cv, sg)
        st.subheader("Hasil penyisipan terakhir")
        st.caption(f"Format {result['format']} · {info['mode']} · ECC {info['ecc']} · payload {result['name']}")
        show_metrics({"PSNR (dB)": fmt(q["PSNR_dB"], 2), "SSIM": fmt(q["SSIM"], 5),
                      "MSE": fmt(q["MSE"]), "Waktu + verifikasi": f"{result['elapsed']:.0f} ms"})
        a, b, c = st.columns(3)
        a.image(cv, caption="Cover asli", **FIT)
        b.image(sg, caption="Stego dari berkas hasil simpan", **FIT)
        diff = np.clip(np.abs(cv.astype(int) - sg.astype(int)) * 20, 0, 255).astype(np.uint8)
        c.image(diff, caption="Selisih diperbesar ×20", **FIT)
        ext, mime = ("jpg", "image/jpeg") if result["format"] == "JPEG" else ("png", "image/png")
        st.download_button(f"Unduh stego.{ext}", result["encoded"], f"stego.{ext}", mime)
        with st.expander("Detail teknis"):
            st.json(dict(metode=info["mode"], backend=info["backend"], ecc=info["ecc"],
                         kompresi=info["compressed"], k_Hamming=info["k"], blob_byte=info["blob_len"],
                         nilai_kanal_berubah=info["changed"], entropi_ciphertext=M.entropy_bytes(info["ciphertext"]),
                         verifikasi_berkas=info["verified"]))

with tabs[1]:
    target = target_selector("extract")
    pw = st.text_input("Password ekstraksi", type="password", key="extract_password")
    if target is not None:
        token = (image_key(target["stego"]), hashlib.sha256(pw.encode()).hexdigest())
        if st.button("Ekstrak & dekripsi", type="primary", disabled=not pw):
            S.pop("extracted", None)
            try:
                with st.spinner("Membaca dan mendekripsi pesan..."):
                    out = transport.extract(target["stego"], pw)
                S["extracted"] = dict(token=token, data=out,
                                      identical=out == target["expected"] if target["expected"] is not None else None)
            except sc.ExtractionError as exc:
                st.error(str(exc))
        record = S.get("extracted")
        if record and record["token"] == token:
            out = record["data"]
            st.success(f"Berhasil mengekstrak {len(out):,} byte. Autentikasi GCM valid.")
            if record["identical"] is not None:
                st.write("Identik dengan payload asli:", "Ya" if record["identical"] else "Tidak")
            st.code(f"SHA-256: {hashlib.sha256(out).hexdigest()}")
            try:
                preview = out.decode("utf-8")
                st.text_area("Pratinjau teks (maksimal 4.000 karakter)", preview[:4000], height=150)
                if len(preview) > 4000:
                    st.caption("Pratinjau diringkas; unduhan berisi seluruh payload.")
            except UnicodeDecodeError:
                st.info("Payload biner. Unduh hasil untuk membuka file aslinya.")
            default_name = S.result["name"] if target["expected"] is not None else "hasil_ekstraksi.bin"
            filename = st.text_input("Nama file hasil ekstraksi", default_name, key=f"filename_{token[0][:12]}")
            st.download_button("Unduh hasil ekstraksi", out, os.path.basename(filename) or "hasil_ekstraksi.bin", "application/octet-stream")

# ------------------------------------------------------------------ STEGANALISIS
with tabs[2]:
    target = target_selector("analysis", with_cover=True)
    if target is not None:
        sg, cv = target["stego"], target["cover"]
        token = (image_key(sg), image_key(cv) if cv is not None else None)
        if st.button("Jalankan steganalisis"):
            with st.spinner("Menghitung metrik gambar..."):
                S["analysis_result"] = dict(token=token, stego=live.steganalysis(sg),
                                             cover=live.steganalysis(cv) if cv is not None else None,
                                             quality=live.quality(cv, sg))
        record = S.get("analysis_result")
        if record and record["token"] == token:
            frame = pd.DataFrame([record["stego"]], index=["Stego"])
            if record["cover"] is not None:
                frame.loc["Cover"] = record["cover"]
            st.dataframe(frame, **FIT)
            q = record["quality"]
            show_metrics({"PSNR (dB)": fmt(q["PSNR_dB"], 2), "SSIM": fmt(q["SSIM"], 5), "MSE": fmt(q["MSE"])})
            hist = {"Stego": np.bincount(sg.ravel(), minlength=256)}
            if cv is not None:
                hist["Cover"] = np.bincount(cv.ravel(), minlength=256)
            st.write("Histogram nilai kanal (0–255)")
            st.line_chart(pd.DataFrame(hist))
            a, b = st.columns(2)
            a.image(sg, caption="Gambar yang dianalisis", **FIT)
            b.image((sg[..., 1] & 1) * 255, caption="Bidang LSB kanal hijau", **FIT)
            csv_download(frame.reset_index(names="gambar"), "steganalisis.csv", "analysis_csv")
            st.caption("RS dan chi-kuadrat adalah indikator statistik, bukan bukti ada/tidaknya pesan. Keduanya terutama menilai jejak LSB; JPEG/DCT memerlukan detektor khusus untuk penilaian ketidakterdeteksian.")
            if cv is None:
                st.info("Unggah cover asli untuk menampilkan PSNR, SSIM, dan MSE.")

with tabs[3]:
    target = target_selector("attack")
    if target is not None:
        pw = st.text_input("Password untuk menguji pemulihan", type="password", key="attack_password",
                           help="Gunakan password yang sama dengan saat menyisipkan payload.")
        names = [name for name, _ in A.SUITE]
        pick = st.selectbox("Serangan", names)
        selected = st.radio("Cakupan pengujian", ["Serangan terpilih", "Seluruh serangan"], horizontal=True)
        token = (image_key(target["stego"]), hashlib.sha256(pw.encode()).hexdigest())
        if st.button("Jalankan uji serangan", disabled=not pw):
            S.pop("attack_result", None)
            baseline_image, baseline = live.run_attack(
                target["stego"], "Tanpa serangan", pw, target["expected"], target["info"])
            if not baseline["autentikasi_valid"]:
                st.error("Validasi tanpa serangan gagal. Periksa password dan pastikan gambar sumber "
                         "memang berisi payload yang disisipkan. Uji serangan dibatalkan.")
            else:
                rows, preview, preview_name = [], None, None
                chosen = names if selected == "Seluruh serangan" else [pick]
                progress = st.progress(0.0)
                with st.spinner("Menguji pemulihan pesan pada setiap serangan..."):
                    for i, name in enumerate(chosen):
                        if name == "Tanpa serangan":
                            attacked, row = baseline_image, baseline
                        else:
                            attacked, row = live.run_attack(
                                target["stego"], name, pw, target["expected"], target["info"])
                        if name == pick or preview is None:
                            preview, preview_name = attacked, name
                        rows.append(row)
                        progress.progress((i + 1) / len(chosen))
                S["attack_result"] = dict(token=token, rows=rows, preview=preview, preview_name=preview_name)
        record = S.get("attack_result")
        if record and record["token"] == token:
            frame = pd.DataFrame(record["rows"])
            show_metrics({"Jumlah uji": len(frame), "Autentikasi valid": int(frame.autentikasi_valid.sum()),
                          "Gagal dipulihkan": int((~frame.autentikasi_valid).sum())})
            st.dataframe(frame, **FIT)
            if target["info"] is not None:
                st.bar_chart(frame.set_index("serangan")[["BER"]])
            if record["preview"] is not None:
                a, b = st.columns(2)
                a.image(target["stego"], caption="Stego sebelum serangan", **FIT)
                b.image(record["preview"], caption=record["preview_name"], **FIT)
                st.download_button("Unduh gambar setelah serangan (PNG)", encode_image(record["preview"]), "hasil_serangan.png", "image/png")
            csv_download(frame, "uji_serangan.csv", "attack_csv")
            st.caption("PSNR/SSIM/MSE dibandingkan dengan stego sebelum serangan. BER dihitung sebelum koreksi ECC. Penghapusan area bawah mempertahankan dimensi; ini bukan pemotongan ukuran gambar.")
            if target["info"] is None:
                st.info("BER dan kecocokan dengan payload asli tidak tersedia untuk unggahan tanpa referensi penyisipan. Autentikasi GCM tetap diperiksa dengan password.")

with tabs[4]:
    st.subheader("Evaluasi gambar pilihan")
    target = target_selector("evaluation", with_cover=True)
    if target is not None:
        pw = st.text_input("Password untuk evaluasi ekstraksi", type="password", key="evaluation_password")
        token = (image_key(target["stego"]), image_key(target["cover"]) if target["cover"] is not None else None,
                 hashlib.sha256(pw.encode()).hexdigest())
        if st.button("Evaluasi gambar ini", disabled=not pw):
            with st.spinner("Mengevaluasi kualitas, steganalisis, dan ekstraksi..."):
                row = live.evaluate(target["cover"], target["stego"], pw, target["expected"], target["info"])
            S["live_evaluation"] = dict(token=token, row=row)
        record = S.get("live_evaluation")
        if record and record["token"] == token:
            row = record["row"]
            (st.success if row["autentikasi_valid"] else st.error)(row["keterangan"])
            show_metrics({"PSNR (dB)": fmt(row["PSNR_dB"], 2), "SSIM": fmt(row["SSIM"], 5),
                          "MSE": fmt(row["MSE"]), "BER": fmt(row["BER"])})
            frame = pd.DataFrame([row])
            st.dataframe(frame, **FIT)
            csv_download(frame, "evaluasi_gambar.csv", "evaluation_csv")
            if target["cover"] is None:
                st.info("PSNR, SSIM, dan MSE memerlukan cover asli. Nilai kosong berarti tidak tersedia.")
    st.divider()
    st.subheader("Arsip eksperimen bawaan")
    st.caption("Data berikut berasal dari eksperimen tersimpan, bukan otomatis dari gambar pilihan di atas. Eksperimen lama memakai LSB; hasilnya tidak mewakili mode DCT/JPEG.")
    result_dir, figures_dir = os.path.join(HERE, "results"), os.path.join(HERE, "figures")
    for filename, title in [("payload_results.csv", "10 ukuran payload"), ("robustness.csv", "Ketahanan terhadap serangan"),
                            ("capacity.csv", "Kapasitas"), ("ml_steganalysis.csv", "Steganalisis ML"),
                            ("bruteforce.csv", "Estimasi brute force")]:
        path = os.path.join(result_dir, filename)
        if os.path.exists(path):
            with st.expander(title):
                try:
                    frame = pd.read_csv(path)
                    st.dataframe(frame, **FIT)
                    csv_download(frame, filename, f"archive_{filename}")
                except (ValueError, OSError) as exc:
                    st.error(f"Tabel tidak dapat dibaca: {exc}")
    if os.path.isdir(figures_dir):
        with st.expander("Grafik eksperimen bawaan"):
            figures = [name for name in sorted(os.listdir(figures_dir)) if name.endswith(".png")]
            if figures:
                filename = st.selectbox("Pilih grafik", figures)
                st.image(os.path.join(figures_dir, filename), caption=filename, **FIT)
