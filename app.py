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
            ),
            st.Page(
                "app_pages/insert.py",
                title="Sisipkan",
                icon=":material/lock:",
            ),
            st.Page(
                "app_pages/extract.py",
                title="Ekstrak",
                icon=":material/lock_open:",
            ),
            st.Page(
                "app_pages/analysis.py",
                title="Steganalisis",
                icon=":material/query_stats:",
            ),
            st.Page(
                "app_pages/attacks.py",
                title="Uji serangan",
                icon=":material/bug_report:",
            ),
            st.Page(
                "app_pages/evaluation.py",
                title="Evaluasi",
                icon=":material/assessment:",
            ),
        ]
    },
    position="sidebar",
)

page.run()
