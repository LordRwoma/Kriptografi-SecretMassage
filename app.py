"""StegoCrypt-X v2 — demo interaktif.   Jalankan:  streamlit run app.py"""
import hashlib, io, os, time
import numpy as np
import pandas as pd
import streamlit as st
from PIL import Image
from skimage import data as skdata
import stegocrypt as sc, metrics as M, attacks as A

st.set_page_config(page_title="StegoCrypt-X", page_icon="🔐", layout="wide")
_v = tuple(int(x) for x in st.__version__.split(".")[:2])
FIT = {"width": "stretch"} if _v >= (1, 50) else {"use_container_width": True}   # kompatibel lintas versi Streamlit
HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = {"astronaut (512×512 RGB)": skdata.astronaut, "coffee (400×600 RGB)": skdata.coffee, "chelsea (300×451 RGB)": skdata.chelsea,
           "rocket (427×640 RGB)": skdata.rocket, "immunohistochemistry (512×512)": skdata.immunohistochemistry}
MODE_LABEL = {"matrix": "Matrix embedding + LSB matching (direkomendasikan)", "match": "LSB matching ±1", "replace": "LSB replacement (naif)"}
ECC_LABEL = {0: "Tanpa ECC (kapasitas maks)", 1: "ECC 1 — RS(255,223)", 2: "ECC 2 — RS(255,191)", 3: "ECC 3 — RS(255,127) tahan banting"}


def to_png(a):
    b = io.BytesIO(); Image.fromarray(a).save(b, format="PNG"); return b.getvalue()


def diff_img(c, s, gain=255):
    return np.clip(np.abs(c.astype(int) - s.astype(int)) * gain, 0, 255).astype(np.uint8)


st.title("🔐 StegoCrypt-X")
st.caption("Kriptografi (AES-256-GCM + scrypt) ⨁ Steganografi (LSB matching + matrix embedding, posisi acak berkunci) — Tugas Akhir Kriptografi & Keamanan Data")

with st.sidebar:
    st.header("⚙️ Pengaturan")
    password = st.text_input("Password", value="demo-pass-2026", type="password")
    mode = st.radio("Metode penyisipan", list(MODE_LABEL), format_func=MODE_LABEL.get)
    ecc = st.selectbox("Ketahanan (Reed-Solomon)", list(ECC_LABEL), format_func=ECC_LABEL.get,
                       help="ECC>0 membuat pesan tahan noise/cropping ringan, tetapi mengurangi kapasitas. Memaksa k=1.")
    compress = st.checkbox("Kompres zlib sebelum enkripsi", help="Menaikkan kapasitas efektif untuk teks.")
    st.divider()
    src = st.radio("Citra sampul", ["Contoh bawaan", "Unggah sendiri"])
    if src == "Contoh bawaan":
        nm = st.selectbox("Pilih contoh", list(SAMPLES)); cover = SAMPLES[nm]()
    else:
        up = st.file_uploader("PNG/JPG/BMP", type=["png", "jpg", "jpeg", "bmp"])
        cover = np.array(Image.open(up).convert("RGB")) if up else skdata.astronaut()
        if not up: st.info("Belum ada unggahan — memakai contoh astronaut.")
    cap = sc.capacity_bytes(cover.shape, ecc)
    st.metric("Kapasitas maks (data acak)", f"{cap:,} B", f"{8 * cap / (cover.shape[0] * cover.shape[1]):.2f} bpp")

S = st.session_state
tabs = st.tabs(["🔐 Sisipkan", "🔓 Ekstrak", "🕵️ Steganalisis", "💥 Uji serangan", "📊 Hasil evaluasi"])

# ------------------------------------------------------------------ SISIPKAN
with tabs[0]:
    c1, c2 = st.columns([1, 1])
    with c1:
        kind = st.radio("Sumber payload", ["Teks", "File"], horizontal=True)
        if kind == "Teks":
            txt = st.text_area("Pesan rahasia", "Halo dosen! Ini pesan rahasia untuk Tugas Akhir Kriptografi & Keamanan Data. 🔐", height=130)
            payload = txt.encode()
        else:
            f = st.file_uploader("File payload (apa saja)", key="pl"); payload = f.read() if f else b""
        st.write(f"Ukuran payload: **{len(payload):,} B** — terpakai **{100 * len(payload) / max(cap, 1):.2f}%** kapasitas")
        st.progress(min(len(payload) / max(cap, 1), 1.0))
        go = st.button("🚀 Enkripsi & sisipkan", type="primary", disabled=not payload)
    if go:
        try:
            t = time.perf_counter(); s_img, info = sc.embed(cover, payload, password, mode=mode, ecc=ecc, compress=compress); dt = time.perf_counter() - t
            S.update(cover=cover, stego=s_img, info=info, payload=payload, dt=dt, pw=password)
        except ValueError as e:
            st.error(str(e))
    if "stego" in S:
        cv, sg, inf = S.cover, S.stego, S.info
        m = st.columns(6)
        m[0].metric("PSNR", f"{M.psnr(cv, sg):.2f} dB"); m[1].metric("SSIM", f"{M.ssim(cv, sg):.5f}"); m[2].metric("MSE", f"{M.mse(cv, sg):.4f}")
        m[3].metric("k Hamming", inf["k"]); m[4].metric("Nilai berubah", f"{100 * inf['changed'] / cv.size:.3f}%"); m[5].metric("Waktu", f"{S.dt * 1000:.0f} ms")
        i1, i2, i3 = st.columns(3)
        i1.image(cv, caption="Cover asli", **FIT); i2.image(sg, caption="Stego-image", **FIT)
        i3.image(diff_img(cv, sg), caption="|Selisih| ×255 — titik terang = nilai yang diubah", **FIT)
        st.download_button("⬇️ Unduh stego.png (lossless)", to_png(sg), "stego.png", "image/png")
        with st.expander("🔬 Detail teknis"):
            st.json(dict(salt=inf["salt"].hex(), nonce=inf["nonce"].hex(), header_hex=inf["header"].hex(), blob_bytes=inf["blob_len"],
                         ciphertext_entropy=round(M.entropy_bytes(inf["ciphertext"]), 4), bit_tersisip=inf["n_bits"],
                         efisiensi_bit_per_perubahan=round(inf["efficiency"], 2), ecc=inf["ecc"], zlib=inf["compressed"]))

# ------------------------------------------------------------------ EKSTRAK
with tabs[1]:
    sel = st.radio("Sumber stego", ["Stego terakhir (tab Sisipkan)", "Unggah stego.png"], horizontal=True)
    pw2 = st.text_input("Password ekstraksi", value=password, type="password", key="pw2")
    target = None
    if sel.startswith("Stego terakhir"):
        target = S.get("stego")
        if target is None: st.info("Belum ada stego — buat dulu di tab Sisipkan.")
    else:
        u = st.file_uploader("stego.png", type=["png"], key="up_st")
        if u: target = np.array(Image.open(u).convert("RGB"))
    if target is not None and st.button("🔓 Ekstrak & dekripsi"):
        try:
            out = sc.extract(target, pw2)
            st.success(f"Berhasil: {len(out):,} B diekstrak, tag GCM valid ✔")
            st.code(f"SHA-256: {hashlib.sha256(out).hexdigest()}")
            if "payload" in S and sel.startswith("Stego terakhir"):
                st.write("Identik dengan payload asli:", "✅ ya" if out == S.payload else "❌ tidak")
            try: st.text_area("Isi (teks)", out.decode(), height=120)
            except UnicodeDecodeError: st.info("Payload biner — gunakan tombol unduh.")
            st.download_button("⬇️ Unduh hasil ekstraksi", out, "hasil_ekstraksi.bin")
        except sc.ExtractionError as e:
            st.error(f"DITOLAK: {e}")

# ------------------------------------------------------------------ STEGANALISIS
with tabs[2]:
    if "stego" not in S: st.info("Buat stego dulu di tab Sisipkan.")
    else:
        cv, sg = S.cover, S.stego; g = 1 if cv.ndim == 3 else None
        a, b, c = st.columns(3)
        a.metric("RS estimasi (cover → stego)", f"{M.rs_estimate(sg):.4f}", f"cover {M.rs_estimate(cv):.4f}", delta_color="off")
        b.metric("χ² p-value (≈1 = terdeteksi)", f"{M.chi2_pvalue(sg):.3g}", f"cover {M.chi2_pvalue(cv):.3g}", delta_color="off")
        c.metric("Korelasi horizontal", f"{M.adjacent_corr(sg):.5f}", f"cover {M.adjacent_corr(cv):.5f}", delta_color="off")
        lo, hi = 90, 130; hc, hs = np.bincount(cv.ravel(), minlength=256)[lo:hi], np.bincount(sg.ravel(), minlength=256)[lo:hi]
        st.write("**Histogram nilai piksel (90–130):** cover vs stego"); st.bar_chart(pd.DataFrame({"cover": hc, "stego": hs}, index=np.arange(lo, hi)))
        p1, p2 = st.columns(2)
        ch = (lambda x: x[..., 1]) if g else (lambda x: x)
        p1.image((ch(cv) & 1) * 255, caption="Bidang LSB cover", **FIT); p2.image((ch(sg) & 1) * 255, caption="Bidang LSB stego (acak, tanpa pola)", **FIT)
        st.caption("Cara baca: LSB replacement → pasangan nilai (2k, 2k+1) terekualisasi (histogram 'tangga', χ²→1). LSB matching & matrix embedding tidak meninggalkan jejak itu.")

# ------------------------------------------------------------------ SERANGAN
with tabs[3]:
    if "stego" not in S: st.info("Buat stego dulu di tab Sisipkan.")
    else:
        names = [n for n, _ in A.SUITE]; pick = st.selectbox("Serangan", names, index=7)
        att = dict(A.SUITE)[pick](S.stego)
        k1, k2 = st.columns(2); k1.image(att, caption=f"Setelah: {pick}", **FIT)
        try:
            out = sc.extract(att, S.pw); okx = out == S.payload
        except sc.ExtractionError as e:
            okx, err = False, str(e)
        with k2:
            st.metric("PSNR vs stego", f"{M.psnr(S.stego, att):.2f} dB" if pick != names[0] else "∞")
            st.metric("BER bit tersisip", f"{M.ber(S.info['body_bits'], sc.read_body_bits(att, S.info)):.4f}")
            st.success("Payload pulih utuh ✔") if okx else st.error(f"Ekstraksi gagal: {err}")
        st.caption("LSB secara inheren rapuh (JPEG/noise/filter mengacak LSB). Mode ECC 2–3 menambah ketahanan terhadap noise impuls & cropping ringan.")

# ------------------------------------------------------------------ HASIL EVALUASI
with tabs[4]:
    R, F = os.path.join(HERE, "results"), os.path.join(HERE, "figures")
    if not os.path.isdir(R) or not os.listdir(R): st.warning("Jalankan `python evaluate.py` untuk menghasilkan hasil evaluasi.")
    else:
        for csv, title in [("payload_results.csv", "Tabel 10 payload (cover astronaut)"), ("robustness.csv", "Robustness"), ("capacity.csv", "Kapasitas"),
                           ("ml_steganalysis.csv", "Steganalisis ML (AUC)"), ("bruteforce.csv", "Estimasi brute force password")]:
            p = os.path.join(R, csv)
            if os.path.exists(p):
                with st.expander(f"📄 {title}", expanded=(csv == "payload_results.csv")): st.dataframe(pd.read_csv(p), **FIT)
        for img in sorted(os.listdir(F)) if os.path.isdir(F) else []:
            if img.endswith(".png"): st.image(os.path.join(F, img), caption=img, **FIT)
