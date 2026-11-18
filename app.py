"""StegoCrypt-X web app. Run with: streamlit run app.py"""
import streamlit as st

st.set_page_config(page_title="StegoCrypt-X", page_icon="🔐", layout="wide")

page = st.navigation(
    {
        "StegoCrypt-X": [
            st.Page(
                "app_pages/home.py",
                title="Beranda",
                icon=":material/home:",
                help="Ringkasan aplikasi, status hasil sesi, dan panduan singkat penggunaan.",
            ),
            st.Page(
                "app_pages/insert.py",
                title="Sisipkan",
                icon=":material/lock:",
                help="Enkripsi payload dan sisipkan ke sampul raster atau SVG. Hasil tetap PNG/JPEG.",
            ),
            st.Page(
                "app_pages/extract.py",
                title="Ekstrak",
                icon=":material/lock_open:",
                help="Ekstrak payload dari gambar stego dengan password penyisipan.",
            ),
            st.Page(
                "app_pages/analysis.py",
                title="Steganalisis",
                icon=":material/query_stats:",
                help="Periksa indikator statistik gambar dan metrik kualitas jika cover tersedia.",
            ),
            st.Page(
                "app_pages/attacks.py",
                title="Uji serangan",
                icon=":material/bug_report:",
                help="Uji pemulihan payload setelah gambar mengalami gangguan atau serangan.",
            ),
            st.Page(
                "app_pages/evaluation.py",
                title="Evaluasi",
                icon=":material/assessment:",
                help="Evaluasi gambar aktif dan lihat arsip eksperimen historis secara terpisah.",
            ),
        ]
    },
    position="sidebar",
)

page.run()
