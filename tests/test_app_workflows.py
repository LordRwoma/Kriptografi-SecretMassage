"""Exercise actual Streamlit widgets, reruns, and session-scoped results."""
import importlib.util
import os
import unittest

HAS_STREAMLIT = importlib.util.find_spec("streamlit") is not None


@unittest.skipUnless(HAS_STREAMLIT, "Streamlit is not installed")
class TestAppWorkflows(unittest.TestCase):
    def run_workflow(self, output_format):
        from streamlit.testing.v1 import AppTest
        app = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
        at = AppTest.from_file(app, default_timeout=40).run()
        at.switch_page("app_pages/insert.py").run()

        def button(label):
            return next(widget for widget in at.button if widget.label == label)

        def no_error():
            self.assertEqual([error.message for error in at.exception], [])

        no_error()
        at.text_input(key="insert_password").set_value("uji-gui-2026").run()
        next(w for w in at.selectbox if w.label == "Format hasil stego").set_value(output_format).run()
        button("Enkripsi & sisipkan").click().run()
        no_error()
        self.assertEqual(at.session_state["result"]["format"], output_format)
        at.switch_page("app_pages/extract.py").run()
        at.text_input(key="extract_password").set_value("uji-gui-2026").run()
        button("Ekstrak & dekripsi").click().run()
        no_error()
        original = at.session_state["result"]["payload"]
        self.assertEqual(at.session_state["extracted"]["data"], original)
        self.assertEqual(sum("Berhasil mengekstrak" in w.value for w in at.success), 1)
        self.assertEqual(sum(w.label.startswith("Pratinjau teks") for w in at.text_area), 1)
        at.run()
        self.assertTrue(any("Autentikasi GCM valid" in w.value for w in at.success))

        at.switch_page("app_pages/analysis.py").run()
        button("Jalankan steganalisis").click().run()
        no_error()
        self.assertIn("quality", at.session_state["analysis_result"])

        at.switch_page("app_pages/attacks.py").run()
        at.text_input(key="attack_password").set_value("uji-gui-2026").run()
        next(w for w in at.radio if w.label == "Cakupan pengujian").set_value("Seluruh serangan").run()
        self.assertTrue(next(w for w in at.selectbox if w.label == "Serangan").disabled)
        button("Jalankan uji serangan").click().run()
        no_error()
        rows = at.session_state["attack_result"]["rows"]
        import attacks as A
        self.assertEqual(len(rows), len(A.ATTACK_SUITE))
        self.assertTrue(rows[0]["payload_identik"])
        at.run()
        self.assertEqual(at.session_state["attack_result"]["rows"], rows)

        at.switch_page("app_pages/evaluation.py").run()
        at.text_input(key="evaluation_password").set_value("uji-gui-2026").run()
        button("Evaluasi gambar ini").click().run()
        no_error()
        self.assertTrue(at.session_state["live_evaluation"]["row"]["payload_identik"])

        at.switch_page("app_pages/extract.py").run()
        at.text_input(key="extract_password").set_value("salah").run()
        button("Ekstrak & dekripsi").click().run()
        no_error()
        self.assertTrue(any("Password salah dan kerusakan data" in w.value for w in at.error))
        self.assertNotIn("extracted", at.session_state)

    def test_png_workflow(self):
        self.run_workflow("PNG")

    def test_jpeg_workflow(self):
        self.run_workflow("JPEG")

    def test_attack_suite_requires_valid_baseline(self):
        from streamlit.testing.v1 import AppTest
        app = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
        at = AppTest.from_file(app, default_timeout=40).run()
        at.switch_page("app_pages/insert.py").run()
        at.text_input(key="insert_password").set_value("uji-gui-2026").run()
        next(widget for widget in at.button if widget.label == "Enkripsi & sisipkan").click().run()
        at.switch_page("app_pages/attacks.py").run()
        at.text_input(key="attack_password").set_value("password-salah").run()
        next(widget for widget in at.button if widget.label == "Jalankan uji serangan").click().run()
        self.assertNotIn("attack_result", at.session_state)
        self.assertTrue(any("Validasi tanpa serangan gagal" in error.value for error in at.error))

    def test_oversize_payload_disables_embed(self):
        from streamlit.testing.v1 import AppTest
        app = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
        at = AppTest.from_file(app, default_timeout=40).run()
        at.switch_page("app_pages/insert.py").run()
        at.text_input(key="insert_password").set_value("uji-gui-2026").run()
        next(widget for widget in at.radio if widget.label == "Sumber payload").set_value("File").run()
        at.file_uploader(key="payload_upload").set_value(
            ("oversize.bin", b"x" * 120_000, "application/octet-stream")).run()
        button = next(widget for widget in at.button if widget.label == "Enkripsi & sisipkan")
        self.assertTrue(button.disabled)
        self.assertTrue(any("Payload melebihi kapasitas" in warning.value for warning in at.warning))

    def test_small_jpeg_cover_explains_zero_capacity(self):
        from streamlit.testing.v1 import AppTest
        import numpy as np
        from image_io import encode_image

        app = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
        at = AppTest.from_file(app, default_timeout=40).run()
        at.switch_page("app_pages/insert.py").run()
        next(widget for widget in at.selectbox if widget.label == "Format hasil stego").set_value("JPEG").run()
        next(widget for widget in at.radio if widget.label == "Citra sampul").set_value("Unggah sendiri").run()
        image_bytes = encode_image(np.zeros((64, 64, 3), dtype=np.uint8))
        at.file_uploader(key="cover_upload").set_value(("small.png", image_bytes, "image/png")).run()
        self.assertTrue(any("tidak memiliki kapasitas" in warning.value for warning in at.warning))

    def test_svg_upload_limit_is_explained(self):
        from streamlit.testing.v1 import AppTest

        app = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
        at = AppTest.from_file(app, default_timeout=40).run()
        at.switch_page("app_pages/insert.py").run()
        next(widget for widget in at.radio if widget.label == "Citra sampul").set_value("Unggah sendiri").run()
        self.assertTrue(any("Batas khusus SVG: 20 MiB" in caption.value for caption in at.caption))

    def test_source_selectors_have_distinct_labels(self):
        from streamlit.testing.v1 import AppTest
        app = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
        at = AppTest.from_file(app, default_timeout=40).run()
        page_labels = (
            ("app_pages/extract.py", "Sumber gambar untuk ekstraksi"),
            ("app_pages/analysis.py", "Sumber gambar untuk steganalisis"),
            ("app_pages/attacks.py", "Sumber gambar untuk uji serangan"),
            ("app_pages/evaluation.py", "Sumber gambar untuk evaluasi"),
        )
        for path, label in page_labels:
            with self.subTest(page=path):
                at.switch_page(path).run()
                self.assertEqual(at.radio[0].label, label)

    def test_custom_stego_filename_keeps_selected_extension(self):
        from streamlit.testing.v1 import AppTest

        app = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
        at = AppTest.from_file(app, default_timeout=40).run()
        at.switch_page("app_pages/insert.py").run()
        at.text_input(key="insert_password").set_value("uji-gui-2026").run()
        at.text_input[1].set_value("kelas-final.jpg").run()
        next(widget for widget in at.selectbox if widget.label == "Format hasil stego").set_value("PNG").run()
        next(widget for widget in at.button if widget.label == "Enkripsi & sisipkan").click().run()
        self.assertEqual(at.session_state["result"]["filename"], "kelas-final.png")

    def test_homepage_shows_dashboard_and_usage_guide(self):
        from streamlit.testing.v1 import AppTest

        app = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
        at = AppTest.from_file(app, default_timeout=40).run()
        self.assertEqual([error.message for error in at.exception], [])
        self.assertEqual(at.title[0].value, "Beranda StegoCrypt-X")
        self.assertTrue(any("Cara menggunakan" in block.value for block in at.header))
        self.assertTrue(any("Belum ada hasil" in metric.value for metric in at.metric))

    def test_benchmark_page_runs_without_overwriting_stego(self):
        from streamlit.testing.v1 import AppTest
        import numpy as np

        app = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
        at = AppTest.from_file(app, default_timeout=60).run()
        cover = np.full((64, 64, 3), 120, np.uint8)
        # The benchmark only consumes the cover from this record.
        at.session_state["result"] = dict(cover=cover, stego=cover.copy(), payload=b"original",
                                           format="PNG", info=dict(verified=True))
        at.switch_page("app_pages/benchmark.py").run()
        at.radio(key="benchmark_source").set_value("Cover penyisipan terakhir").run()
        at.radio(key="benchmark_sizing").set_value("Ukuran manual (byte)").run()
        next(w for w in at.text_input if w.label == "Daftar ukuran byte, pisahkan dengan koma").set_value("16,32").run()
        next(w for w in at.number_input if w.label == "Pengulangan terukur").set_value(1).run()
        at.text_input(key="benchmark_password").set_value("test-benchmark-ui").run()
        next(w for w in at.button if w.label == "Jalankan benchmark").click().run()
        self.assertEqual([error.message for error in at.exception], [])
        self.assertFalse(at.session_state["benchmark_result"]["errors"])
        self.assertEqual(len(at.session_state["benchmark_result"]["rows"]), 10)
        self.assertEqual(at.session_state["result"]["payload"], b"original")
        np.testing.assert_array_equal(at.session_state["result"]["cover"], cover)
        self.assertTrue(at.session_state["benchmark_zip"].startswith(b"PK"))
        at.run()
        self.assertEqual([error.message for error in at.exception], [])
        self.assertEqual(len(at.session_state["benchmark_result"]["rows"]), 10)
