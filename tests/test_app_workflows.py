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

        def button(label):
            return next(widget for widget in at.button if widget.label == label)

        def no_error():
            self.assertEqual([error.message for error in at.exception], [])

        no_error()
        at.sidebar.text_input[0].set_value("uji-gui-2026").run()
        next(w for w in at.sidebar.selectbox if w.label == "Format hasil stego").set_value(output_format).run()
        button("Enkripsi & sisipkan").click().run()
        no_error()
        self.assertEqual(at.session_state["result"]["format"], output_format)
        at.text_input(key="extract_password").set_value("uji-gui-2026").run()
        button("Ekstrak & dekripsi").click().run()
        no_error()
        original = at.session_state["result"]["payload"]
        self.assertEqual(at.session_state["extracted"]["data"], original)
        at.run()
        self.assertTrue(any("Autentikasi GCM valid" in w.value for w in at.success))
        button("Jalankan steganalisis").click().run()
        no_error()
        self.assertIn("quality", at.session_state["analysis_result"])
        at.text_input(key="attack_password").set_value("uji-gui-2026").run()
        next(w for w in at.radio if w.label == "Cakupan pengujian").set_value("Seluruh serangan").run()
        button("Jalankan uji serangan").click().run()
        no_error()
        rows = at.session_state["attack_result"]["rows"]
        self.assertEqual(len(rows), 16)
        self.assertTrue(rows[0]["payload_identik"])
        at.run()
        self.assertEqual(at.session_state["attack_result"]["rows"], rows)
        at.text_input(key="evaluation_password").set_value("uji-gui-2026").run()
        button("Evaluasi gambar ini").click().run()
        no_error()
        self.assertTrue(at.session_state["live_evaluation"]["row"]["payload_identik"])
        at.text_input(key="extract_password").set_value("salah").run()
        button("Ekstrak & dekripsi").click().run()
        no_error()
        self.assertTrue(any("Pesan tidak dapat dipulihkan" in w.value for w in at.error))
        self.assertNotIn("extracted", at.session_state)

    def test_png_workflow(self):
        self.run_workflow("PNG")

    def test_jpeg_workflow(self):
        self.run_workflow("JPEG")

    def test_attack_suite_requires_valid_baseline(self):
        from streamlit.testing.v1 import AppTest
        app = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
        at = AppTest.from_file(app, default_timeout=40).run()
        at.sidebar.text_input[0].set_value("uji-gui-2026").run()
        next(widget for widget in at.button if widget.label == "Enkripsi & sisipkan").click().run()
        at.text_input(key="attack_password").set_value("password-salah").run()
        next(widget for widget in at.button if widget.label == "Jalankan uji serangan").click().run()
        self.assertNotIn("attack_result", at.session_state)
        self.assertTrue(any("Validasi tanpa serangan gagal" in error.value for error in at.error))
