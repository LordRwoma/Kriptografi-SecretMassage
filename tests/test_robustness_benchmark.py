"""Regression coverage for geometry attacks and the isolated benchmark pipeline."""
import io
import json
import unittest
from unittest.mock import patch
import zipfile

import numpy as np

import attacks as A
import benchmark_service as bench
import image_stego as transport


class TestRobustness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cover = np.random.default_rng(9).integers(30, 225, (64, 80, 3), dtype=np.uint8)
        cls.payload = b"referensi robustness"
        cls.saved, cls.info, _ = transport.embed(cls.cover, cls.payload, "uji-robustness")

    def test_all_extended_attacks_accept_rgb_and_gray_without_mutating_input(self):
        for image in (self.cover, self.cover[..., 0]):
            original = image.copy()
            for name, operation in A.ATTACK_SUITE:
                with self.subTest(serangan=name, shape=image.shape):
                    out = operation(image)
                    self.assertEqual(out.dtype, np.uint8)
                    self.assertGreater(min(out.shape[:2]), 0)
                    self.assertEqual(out.ndim, image.ndim)
                    np.testing.assert_array_equal(image, original)

    def test_crop_and_resize_do_not_crash_or_invent_metrics(self):
        import analysis_service as live
        for name in ("Crop tengah, potong 25% tiap dimensi", "Resize 50% bilinear, dimensi berubah"):
            attacked, report = live.run_attack(self.saved, name, "uji-robustness", self.payload, self.info)
            self.assertNotEqual(attacked.shape, self.saved.shape)
            for key in ("MSE", "PSNR_dB", "SSIM", "BER"):
                self.assertIsNone(report[key])
            self.assertFalse(report["autentikasi_valid"])
            self.assertIn("dimensi", report["status_BER"])
            self.assertTrue(report["keterangan"])

    def test_baseline_and_reproducible_seeded_attacks(self):
        import analysis_service as live
        _, report = live.run_attack(self.saved, "Tanpa serangan", "uji-robustness", self.payload, self.info)
        self.assertTrue(report["payload_identik"])
        self.assertEqual(report["BER"], 0)
        for operation in (A.gauss_noise(10), A.salt_pepper(.05), A.erase_area(.25, True)):
            np.testing.assert_array_equal(operation(self.cover), operation(self.cover))

    def test_bad_ber_reference_does_not_prevent_valid_extraction(self):
        import analysis_service as live
        broken = dict(self.info, sel=np.array([10**9]))
        _, report = live.run_attack(self.saved, "Tanpa serangan", "uji-robustness", self.payload, broken)
        self.assertIsNone(report["BER"])
        self.assertTrue(report["payload_identik"])


class TestBenchmark(unittest.TestCase):
    config = dict(format="PNG", mode="matrix", ecc=0, compress=False, repeats=1, seed=2026)

    def test_sizes_and_capacity_validation(self):
        self.assertEqual(len(set(bench.payload_sizes(100))), 10)
        with self.assertRaises(ValueError):
            bench.payload_sizes(9)
        with self.assertRaises(ValueError):
            list(bench.run_benchmark(np.zeros((16, 16, 3), np.uint8), "test", self.config, sizes=[100000]))

    def test_real_child_worker_timing_memory_and_exports(self):
        cover = np.random.default_rng(0).integers(30, 225, (64, 64, 3), dtype=np.uint8)
        original = cover.copy()
        results = list(bench.run_benchmark(cover, "secret-benchmark-password", self.config, sizes=[16, 32]))
        self.assertEqual(len(results), 2)
        self.assertNotEqual(results[0]["metadata"]["pid"], results[1]["metadata"]["pid"])
        rows = [row for result in results for row in result["rows"]]
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(row["payload_identik"] for row in rows))
        for row in rows:
            self.assertGreater(row["waktu_ms"], 0)
            self.assertGreater(row["rss_puncak_MiB"], 0)
            self.assertGreaterEqual(row["rss_puncak_MiB"], row["rss_awal_MiB"])
            self.assertGreaterEqual(row["sampel_rss"], 2)
        np.testing.assert_array_equal(cover, original)
        record = dict(rows=rows, config=self.config, scenarios=[r["metadata"] for r in results], errors=[])
        exported = bench.export_zip(record)
        with zipfile.ZipFile(io.BytesIO(exported)) as z:
            self.assertIn("benchmark_summary.csv", z.namelist())
            self.assertEqual(len([n for n in z.namelist() if n.endswith(".png")]), 5)
            self.assertNotIn("secret-benchmark-password", z.read("benchmark_metadata.json").decode())
        self.assertEqual(len(bench.summarize(rows)), 10)

    def test_child_error_is_recorded_and_next_scenario_continues(self):
        cover = np.full((32, 32, 3), 100, np.uint8)
        failure = type("Completed", (), {"returncode": 1, "stdout": json.dumps({"error": "simulated failure"})})()
        with patch("benchmark_service.subprocess.run", return_value=failure):
            results = list(bench.run_benchmark(cover, "test", self.config, sizes=[1, 2]))
        self.assertEqual(len(results), 2)
        self.assertTrue(all("error" in r and "rows" not in r for r in results))

    def test_jpeg_pipeline_has_honest_combined_stage(self):
        cover = np.full((256, 256, 3), 120, np.uint8)
        config = dict(self.config, format="JPEG", mode="match", ecc=3)
        result = next(bench.run_benchmark(cover, "test-jpeg-benchmark", config, sizes=[16]))
        self.assertNotIn("error", result)
        self.assertEqual({row["tahap"] for row in result["rows"]},
                         {"Sisip-simpan-verifikasi JPEG", "Ekstraksi dan cek identik", "Total alur"})
        self.assertTrue(all(row["ecc_aktual"] == 3 for row in result["rows"]))


if __name__ == "__main__":
    unittest.main()
