import hashlib

import pandas as pd
import streamlit as st

import attacks as A
import analysis_service as live
import image_io
from ui_common import S, image_key, show_metrics, target_selector


def render():
    st.title("Uji serangan")
    st.caption("Bandingkan ekstraksi sebelum dan sesudah gangguan pada gambar. Gambar unduhan adalah hasil serangan.")
    target = target_selector("attack")
    if target is None:
        return

    password = st.text_input(
        "Password untuk menguji pemulihan",
        type="password",
        key="attack_password",
        help="Gunakan password yang sama dengan saat menyisipkan payload.",
    )
    st.caption("Isi password, lalu jalankan pengujian. Menekan Enter saja tidak memulai tes.")
    selected = st.radio(
        "Cakupan pengujian",
        ["Serangan terpilih", "Seluruh serangan"],
        horizontal=True,
        key="attack_scope",
    )
    category = st.selectbox("Kelompok serangan", ["Semua kelompok"] + sorted(
        {details["kategori"] for details in A.DETAILS.values() if details["kategori"] != "Kontrol"}))
    levels = st.multiselect("Tingkat gangguan", ["Ringan", "Sedang", "Berat"],
                            default=["Ringan", "Sedang", "Berat"])
    names = [name for name, _ in A.ATTACK_SUITE if name == "Tanpa serangan" or
             (A.DETAILS[name]["tingkat"] in levels and
              (category == "Semua kelompok" or A.DETAILS[name]["kategori"] == category))]
    attack_name = st.selectbox(
        "Serangan",
        names,
        disabled=selected == "Seluruh serangan",
        help="Pilih satu serangan; daftar dinonaktifkan saat seluruh suite dijalankan.",
    )
    st.caption(f"{len(names)} pengujian termasuk kontrol tanpa serangan. "
               "Tingkat ringan/sedang/berat adalah pengaturan gangguan, bukan jaminan payload pulih.")
    if selected == "Serangan terpilih":
        st.caption(A.DETAILS[attack_name]["parameter"])
    token = (image_key(target["stego"]), hashlib.sha256(password.encode()).hexdigest())
    if not password:
        st.caption("Isi password untuk mengaktifkan tombol uji serangan.")

    if st.button("Jalankan uji serangan", type="primary", disabled=not password):
        S.pop("attack_result", None)
        baseline_image, baseline = live.run_attack(
            target["stego"], "Tanpa serangan", password, target["expected"], target["info"]
        )
        if not baseline["autentikasi_valid"]:
            st.error(
                "Validasi tanpa serangan gagal. Periksa password dan pastikan gambar sumber "
                "memang berisi payload yang disisipkan. Uji serangan dibatalkan."
            )
        else:
            chosen = names if selected == "Seluruh serangan" else [attack_name]
            rows, preview, preview_name = [], None, None
            progress = st.progress(0.0)
            with st.spinner("Menguji pemulihan pesan..."):
                for index, name in enumerate(chosen):
                    if name == "Tanpa serangan":
                        attacked, row = baseline_image, baseline
                    else:
                        attacked, row = live.run_attack(
                            target["stego"], name, password, target["expected"], target["info"]
                        )
                    if name == attack_name or preview is None:
                        preview, preview_name = attacked, name
                    rows.append(row)
                    progress.progress((index + 1) / len(chosen))
            S["attack_result"] = dict(token=token, rows=rows, preview=preview, preview_name=preview_name)

    record = S.get("attack_result")
    if not record or record["token"] != token:
        return
    frame = pd.DataFrame(record["rows"])
    show_metrics({
        "Jumlah uji": len(frame),
        "Autentikasi valid": int(frame.autentikasi_valid.sum()),
        "Gagal dipulihkan": int((~frame.autentikasi_valid).sum()),
    })
    st.dataframe(frame, hide_index=True)
    st.caption("Tabel ini adalah hasil pengujian terakhir; pilihan di atas diterapkan saat tombol uji ditekan. "
               "PSNR/SSIM/MSE membandingkan stego sebelum dan sesudah serangan. "
               "Waktu ekstraksi dipisahkan dari waktu total uji.")
    st.download_button("Unduh tabel robustness (CSV)", live.attack_csv(record["rows"]),
                       "robustness.csv", "text/csv")
    if frame["BER"].notna().any():
        st.bar_chart(frame.set_index("serangan")[["BER"]])
    st.bar_chart(frame.groupby("kategori")[["autentikasi_valid"]].mean().rename(
        columns={"autentikasi_valid": "Proporsi autentikasi valid"}))
    st.caption("Proporsi di atas hanya merangkum skenario dalam pengujian ini; bukan peluang ketahanan umum.")
    if record["preview"] is not None:
        preview_name = st.selectbox("Pratinjau hasil serangan", frame.serangan.tolist(), key="attack_preview_name")
        preview = dict(A.ATTACK_SUITE)[preview_name](target["stego"])
        left, right = st.columns(2)
        left.image(target["stego"], caption="Stego sebelum serangan", width="stretch")
        right.image(preview, caption=f"Hasil: {preview_name}", width="stretch")
        st.download_button(
            "Unduh gambar hasil serangan (PNG)",
            image_io.encode_image(preview),
            "hasil_serangan.png",
            "image/png",
            help="Unduhan berisi gambar setelah serangan dipilih; untuk 'Tanpa serangan' piksel tetap sama, hanya disimpan sebagai PNG.",
        )
    st.caption("JPEG, noise, filter, dan resize dapat merusak bit stego. Kegagalan pada serangan tersebut adalah hasil ketahanan, bukan otomatis bug. Kondisi 'Tanpa serangan' harus lolos.")
    if target["info"] is None:
        st.info("BER dan kecocokan dengan payload asli tidak tersedia untuk unggahan tanpa referensi penyisipan.")


render()
