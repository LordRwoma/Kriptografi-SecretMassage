"""Regression tests using real serialized images, never a renamed PNG as JPEG."""
import io
import os
import unittest
from PIL import Image, PngImagePlugin
import numpy as np
from skimage import data

import analysis_service as live
import attacks as A
import image_stego as transport
import stegocrypt as sc
from image_io import encode_image, load_image

PASSWORD = "uji-format-2026"


class TestImageWorkflows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cover = data.astronaut()

    def test_jpg_cover_to_png_file_payload_roundtrip(self):
        cover = load_image(io.BytesIO(encode_image(self.cover, "JPEG")))
        payload = bytes(range(256)) * 4
        saved, info, blob = transport.embed(cover, payload, PASSWORD)
        self.assertTrue(blob.startswith(b"\x89PNG"))
        self.assertEqual(transport.extract(load_image(io.BytesIO(blob)), PASSWORD), payload)
        np.testing.assert_array_equal(saved, load_image(io.BytesIO(blob)))
        self.assertTrue(info["verified"])

    def test_real_jpeg_roundtrip_multiple_covers(self):
        # Non-multiple-of-eight dimensions must preserve the same block mapping.
        for cover in (self.cover, data.coffee(), data.chelsea(), self.cover[:509, :503]):
            with self.subTest(shape=cover.shape):
                payload = os.urandom(min(180, transport.capacity_bytes(cover.shape, "JPEG")))
                saved, info, blob = transport.embed(cover, payload, PASSWORD, "JPEG")
                self.assertTrue(blob.startswith(b"\xff\xd8"))
                self.assertEqual(Image.open(io.BytesIO(blob)).format, "JPEG")
                reloaded = load_image(io.BytesIO(blob))
                self.assertEqual(reloaded.shape, cover.shape)
                self.assertEqual(transport.extract(reloaded, PASSWORD), payload)
                self.assertEqual(info["backend"], "dct")
                np.testing.assert_array_equal(saved, reloaded)

    def test_jpeg_improved_visual_quality_and_roundtrip(self):
        payload = os.urandom(800)
        saved, info, encoded = transport.embed(self.cover, payload, PASSWORD, "JPEG")
        self.assertEqual(transport.extract(saved, PASSWORD), payload)
        self.assertTrue(info["verified"])
        self.assertGreater(live.quality(self.cover, saved)["PSNR_dB"], 34)
        self.assertTrue(encoded.startswith(b"\xff\xd8"))

    def test_jpeg_binary_at_capacity_and_over_capacity(self):
        n = transport.capacity_bytes(self.cover.shape, "JPEG")
        payload = os.urandom(n)
        saved, _, _ = transport.embed(self.cover, payload, PASSWORD, "JPEG")
        self.assertEqual(transport.extract(saved, PASSWORD), payload)
        with self.assertRaises(ValueError):
            transport.embed(self.cover, payload + b"x", PASSWORD, "JPEG")

    def test_jpeg_compression_and_wrong_password(self):
        payload = ("Pesan dengan aksara Indonesia: rahasia. " * 120).encode()
        saved, info, _ = transport.embed(self.cover, payload, PASSWORD, "JPEG", compress=True)
        self.assertTrue(info["compressed"])
        self.assertEqual(transport.extract(saved, PASSWORD), payload)
        with self.assertRaises(sc.ExtractionError):
            transport.extract(saved, "password-salah")

    def test_black_and_white_jpeg_covers(self):
        for level in (0, 255):
            with self.subTest(level=level):
                cover = np.full((256, 256, 3), level, np.uint8)
                saved, _, _ = transport.embed(cover, b"pesan pendek", PASSWORD, "JPEG")
                self.assertEqual(transport.extract(saved, PASSWORD), b"pesan pendek")

    def test_evaluation_uses_current_saved_image(self):
        payload = b"evaluasi payload aktual"
        for fmt in ("PNG", "JPEG"):
            with self.subTest(format=fmt):
                saved, info, _ = transport.embed(self.cover, payload, PASSWORD, fmt)
                report = live.evaluate(self.cover, saved, PASSWORD, payload, info)
                self.assertTrue(report["autentikasi_valid"])
                self.assertTrue(report["payload_identik"])
                self.assertGreater(report["PSNR_dB"], 20)
                self.assertIn("chi2_p", report)
                self.assertIsNotNone(report["BER"])

    def test_attack_failure_has_status_and_metrics(self):
        saved, info, _ = transport.embed(self.cover, b"serangan", PASSWORD)
        _, report = live.run_attack(saved, "JPEG Q=75", PASSWORD, b"serangan", info)
        self.assertFalse(report["autentikasi_valid"])
        self.assertTrue(report["keterangan"])
        self.assertGreater(report["BER"], 0)

    def test_uploaded_stego_without_reference_does_not_invent_ber(self):
        saved, _, _ = transport.embed(self.cover, b"unggahan", PASSWORD)
        report = live.evaluate(None, saved, PASSWORD)
        self.assertTrue(report["autentikasi_valid"])
        self.assertIsNone(report["payload_identik"])
        self.assertIsNone(report["BER"])
        self.assertIsNone(report["PSNR_dB"])

    def test_reference_mismatch_and_plain_image_rejected(self):
        saved, info, _ = transport.embed(self.cover, b"asli", PASSWORD)
        _, report = live.run_attack(saved, A.SUITE[0][0], PASSWORD, b"berbeda", info)
        self.assertFalse(report["payload_identik"])
        with self.assertRaises(ValueError):
            live.quality(self.cover[:20], saved)
        with self.assertRaises(sc.ExtractionError):
            transport.extract(self.cover, PASSWORD)

    def test_invalid_upload_and_too_small_jpeg(self):
        with self.assertRaises(ValueError):
            load_image(io.BytesIO(b"not an image"))
        with self.assertRaises(ValueError):
            transport.embed(np.zeros((16, 16, 3), np.uint8), b"x", PASSWORD, "JPEG")

    def test_png_metadata_containing_svg_marker_stays_a_raster_image(self):
        image = Image.new("RGB", (32, 24), "white")
        metadata = PngImagePlugin.PngInfo()
        metadata.add_text("Description", "<svg marker in PNG metadata")
        upload = io.BytesIO()
        image.save(upload, format="PNG", pnginfo=metadata)

        decoded = load_image(io.BytesIO(upload.getvalue()))
        self.assertEqual(decoded.shape, (24, 32, 3))

    def test_svg_cover_rasterizes_to_bounded_png_pixels(self):
        svg = (
            b'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100" '
            b'viewBox="0 0 200 100"><rect width="200" height="100" fill="#ff0000"/></svg>'
        )
        cover = load_image(io.BytesIO(svg), svg_max_edge=512)
        self.assertEqual(cover.shape, (256, 512, 3))
        np.testing.assert_array_equal(cover[128, 256], [255, 0, 0])
        payload = b"vector cover round trip"
        stego, _, encoded = transport.embed(cover, payload, PASSWORD)
        self.assertTrue(encoded.startswith(b"\x89PNG"))
        self.assertEqual(transport.extract(stego, PASSWORD), payload)

    def test_svg_larger_than_two_mib_is_accepted_but_over_limit_is_rejected(self):
        prefix = b'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20">'
        content = b'<rect width="20" height="20" fill="#ff0000"/>'
        suffix = b"</svg>"
        over_two_mib = prefix + b" " * (2 * 1024 * 1024) + content + suffix
        image = load_image(io.BytesIO(over_two_mib))
        self.assertEqual(image.shape, (1024, 1024, 3))

        over_limit = prefix + b" " * (20 * 1024 * 1024) + content + suffix
        with self.assertRaisesRegex(ValueError, "maksimal 20 MiB"):
            load_image(io.BytesIO(over_limit))

    def test_svg_honors_declared_legacy_and_utf16_encodings(self):
        iso_8859_svg = (
            '<?xml version="1.0" encoding="ISO-8859-1"?>'
            '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20">'
            '<!-- café --><rect width="20" height="20" fill="#ff0000"/></svg>'
        ).encode("iso-8859-1")
        self.assertEqual(load_image(io.BytesIO(iso_8859_svg)).shape, (1024, 1024, 3))

        utf16_svg = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20">'
            '<rect width="20" height="20" fill="#00ff00"/></svg>'
        ).encode("utf-16")
        uploaded_svg = io.BytesIO(utf16_svg)
        uploaded_svg.name = "cover.svg"
        self.assertEqual(load_image(uploaded_svg).shape, (1024, 1024, 3))

    def test_svg_with_mismatched_encoding_declaration_has_actionable_error(self):
        svg = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20">'
            b'<!-- \xe9 --><rect width="20" height="20"/></svg>'
        )
        with self.assertRaisesRegex(ValueError, "Periksa deklarasi encoding XML"):
            load_image(io.BytesIO(svg))

    def test_svg_external_resources_and_entities_rejected(self):
        external = (
            b'<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20">'
            b'<image href="https://example.invalid/image.png"/></svg>'
        )
        with self.assertRaisesRegex(ValueError, "referensi gambar eksternal"):
            load_image(io.BytesIO(external))
        entity = (
            b'<!DOCTYPE svg [<!ENTITY x "x">]><svg xmlns="http://www.w3.org/2000/svg" '
            b'width="20" height="20">&x;</svg>'
        )
        with self.assertRaisesRegex(ValueError, "DTD/entity"):
            load_image(io.BytesIO(entity))


if __name__ == "__main__":
    unittest.main()
