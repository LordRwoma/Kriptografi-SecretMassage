"""Serangan/gangguan untuk uji robustness (semuanya mempertahankan dimensi citra)."""
import cv2
import numpy as np


def identity(x): return x.copy()


def jpeg(q):
    def f(x):
        bgr = x if x.ndim == 2 else x[..., ::-1]
        ok, buf = cv2.imencode(".jpg", np.ascontiguousarray(bgr), [cv2.IMWRITE_JPEG_QUALITY, q])
        y = cv2.imdecode(buf, cv2.IMREAD_UNCHANGED)
        return y if x.ndim == 2 else y[..., ::-1].copy()
    return f


def gauss_noise(sigma):
    def f(x):
        n = np.random.default_rng(1).normal(0, sigma, x.shape)
        return np.clip(np.rint(x + n), 0, 255).astype(np.uint8)
    return f


def salt_pepper(p):
    def f(x):
        rng = np.random.default_rng(2); y = x.copy()
        m = rng.random(x.shape)
        y[m < p / 2] = 0; y[m > 1 - p / 2] = 255
        return y
    return f


def median3(x): return cv2.medianBlur(np.ascontiguousarray(x), 3)
def gauss_blur(x): return cv2.GaussianBlur(np.ascontiguousarray(x), (3, 3), 0.8)


def blank_bottom(frac):
    """Cropping 'in-place': area bawah dihitamkan (dimensi tetap, sehingga pemetaan posisi stego tidak bergeser)."""
    def f(x):
        y = x.copy(); y[int(x.shape[0] * (1 - frac)):] = 0
        return y
    return f


def rescale(scale):
    def f(x):
        h, w = x.shape[:2]
        s = cv2.resize(np.ascontiguousarray(x), None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
        return cv2.resize(s, (w, h), interpolation=cv2.INTER_LINEAR)
    return f


SUITE = [
    ("Tanpa serangan", identity),
    ("JPEG Q=95", jpeg(95)),
    ("JPEG Q=75", jpeg(75)),
    ("JPEG Q=50", jpeg(50)),
    ("Noise Gauss σ=1", gauss_noise(1)),
    ("Noise Gauss σ=3", gauss_noise(3)),
    ("Salt&Pepper 0.05%", salt_pepper(0.0005)),
    ("Salt&Pepper 0.1%", salt_pepper(0.001)),
    ("Salt&Pepper 0.5%", salt_pepper(0.005)),
    ("Salt&Pepper 2%", salt_pepper(0.02)),
    ("Median filter 3×3", median3),
    ("Gaussian blur 3×3", gauss_blur),
    ("Penghapusan area bawah 2%", blank_bottom(0.02)),
    ("Penghapusan area bawah 5%", blank_bottom(0.05)),
    ("Penghapusan area bawah 10%", blank_bottom(0.10)),
    ("Resize 50% lalu kembali", rescale(0.5)),
]
