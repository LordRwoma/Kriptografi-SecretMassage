"""Unit test StegoCrypt-X v2.   Jalankan:  python -m pytest -q tests   (atau: python -m unittest discover tests)"""
import os, sys, unittest
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import stegocrypt as sc, metrics as M, attacks as A

rng = np.random.default_rng(0)
COVER = rng.integers(0, 256, (96, 96, 3), dtype=np.uint8)          # cover sintetis kecil (cepat)
PW = "uji-password"
GOLDEN = [173, 956, 520, 328, 903, 962, 163, 843]                  # keluaran _keyed_order(kunci 0..31, n=1000, m=8)


class TestRoundtrip(unittest.TestCase):
    def test_semua_mode_ukuran_ecc_kompresi(self):
        for mode in sc.MODES:
            for ecc in (0, 1, 3):
                for comp in (False, True):
                    for n in (1, 17, 500, 1500):
                        if n > sc.capacity_bytes(COVER.shape, ecc):
                            continue
                        pl = (b"abc " * n)[:n] if comp else os.urandom(n)
                        st, _ = sc.embed(COVER, pl, PW, mode=mode, ecc=ecc, compress=comp)
                        self.assertEqual(sc.extract(st, PW), pl, (mode, ecc, comp, n))

    def test_kapasitas_tepat(self):
        for ecc in (0, 2):
            n = sc.capacity_bytes(COVER.shape, ecc); pl = os.urandom(n)
            st, _ = sc.embed(COVER, pl, PW, ecc=ecc)
            self.assertEqual(sc.extract(st, PW), pl)
            with self.assertRaises(ValueError):
                sc.embed(COVER, os.urandom(n + 1), PW, ecc=ecc)

    def test_cover_grayscale(self):
        g = COVER[..., 0]; pl = os.urandom(300)
        st, _ = sc.embed(g, pl, PW)
        self.assertEqual(st.shape, g.shape); self.assertEqual(sc.extract(st, PW), pl)

    def test_payload_kosong(self):
        st, _ = sc.embed(COVER, b"", PW); self.assertEqual(sc.extract(st, PW), b"")


class TestKeamanan(unittest.TestCase):
    def setUp(self):
        self.pl = os.urandom(400); self.st, self.info = sc.embed(COVER, self.pl, PW)

    def test_password_salah_ditolak(self):
        for i in range(5):
            with self.assertRaises(sc.ExtractionError): sc.extract(self.st, f"salah-{i}")

    def test_tamper_satu_bit_terdeteksi(self):
        for p in self.info["sel"][[0, 7, 100]]:
            t = self.st.reshape(-1).copy(); t[p] ^= 1
            with self.assertRaises(sc.ExtractionError): sc.extract(t.reshape(self.st.shape), PW)

    def test_tamper_header_terdeteksi(self):
        t = self.st.reshape(-1).copy(); t[3] ^= 1
        with self.assertRaises(sc.ExtractionError): sc.extract(t.reshape(self.st.shape), PW)

    def test_cover_tanpa_pesan_ditolak(self):
        with self.assertRaises(sc.ExtractionError): sc.extract(COVER, PW)

    def test_salt_nonce_acak_tiap_embed(self):
        _, i2 = sc.embed(COVER, self.pl, PW)
        self.assertNotEqual(self.info["salt"], i2["salt"]); self.assertNotEqual(self.info["ciphertext"], i2["ciphertext"])

    def test_ecc_koreksi_dan_tidak_pernah_data_salah(self):
        st, info = sc.embed(COVER, self.pl[:200], PW, ecc=3)
        t = st.reshape(-1).copy(); t[info["sel"][10]] ^= 1
        self.assertEqual(sc.extract(t.reshape(st.shape), PW), self.pl[:200])           # 1 error dikoreksi
        t = st.reshape(-1).copy(); t[np.random.default_rng(1).random(t.size) < .25] ^= 1
        with self.assertRaises(sc.ExtractionError): sc.extract(t.reshape(st.shape), PW)  # kerusakan berat ditolak

    def test_header_rusak_dipulihkan_voting(self):
        st, _ = sc.embed(COVER, self.pl[:200], PW, ecc=2)
        t = st.reshape(-1).copy(); t[[0, 5, 40, 100]] ^= 1
        self.assertEqual(sc.extract(t.reshape(st.shape), PW), self.pl[:200])


class TestSteganografi(unittest.TestCase):
    def test_matrix_embedding_mengurangi_perubahan(self):
        pl = os.urandom(300)
        _, a = sc.embed(COVER, pl, PW, mode="matrix"); _, b = sc.embed(COVER, pl, PW, mode="match")
        self.assertGreater(a["k"], 1); self.assertLess(a["changed"], 0.5 * b["changed"])

    def test_perubahan_maks_pm1(self):
        st, _ = sc.embed(COVER, os.urandom(800), PW)
        self.assertLessEqual(np.abs(st.astype(int) - COVER.astype(int)).max(), 1)

    def test_batas_nilai_0_dan_255(self):
        for v in (0, 255):
            c = np.full((64, 64, 3), v, np.uint8); pl = os.urandom(200)
            st, _ = sc.embed(c, pl, PW); self.assertEqual(sc.extract(st, PW), pl)

    def test_permutasi_posisi_stabil_lintas_versi(self):
        """Posisi bergantung PRF AES-CTR + argsort, BUKAN generator NumPy -> harus konstan di semua versi."""
        self.assertEqual(sc._keyed_order(bytes(range(32)), 1000, 8).tolist(), GOLDEN)


class TestMetrik(unittest.TestCase):
    def test_psnr_identik_tak_hingga(self):
        self.assertEqual(M.psnr(COVER, COVER), float("inf")); self.assertEqual(M.mse(COVER, COVER), 0.0)

    def test_ciphertext_acak_entropi_tinggi(self):
        ct = os.urandom(20000); self.assertGreater(M.entropy_bytes(ct), 7.98); self.assertGreater(M.chi2_uniform_bytes(ct), 0.001)

    def test_serangan_menjaga_dimensi(self):
        for _, f in A.SUITE: self.assertEqual(f(COVER).shape, COVER.shape)


if __name__ == "__main__":
    unittest.main()
