"""Reproducible robustness attacks; geometry changes are explicitly described.

SUITE remains a list of (name, callable) for the original evaluation scripts.
DETAILS adds parameters and levels for the interactive evaluator.
"""
import cv2
import numpy as np


def identity(x): return x.copy()


def jpeg(q):
    def f(x):
        bgr = x if x.ndim == 2 else x[..., ::-1]
        ok, buf = cv2.imencode(".jpg", np.ascontiguousarray(bgr), [cv2.IMWRITE_JPEG_QUALITY, q])
        if not ok:
            raise ValueError("Encoding serangan JPEG gagal.")
        y = cv2.imdecode(buf, cv2.IMREAD_UNCHANGED)
        if y is None:
            raise ValueError("Pembacaan hasil serangan JPEG gagal.")
        return y if x.ndim == 2 else y[..., ::-1].copy()
    return f


def gauss_noise(sigma, seed=1):
    def f(x):
        n = np.random.default_rng(seed).normal(0, sigma, x.shape)
        return np.clip(np.rint(x + n), 0, 255).astype(np.uint8)
    return f


def salt_pepper(p, seed=2):
    def f(x):
        rng = np.random.default_rng(seed); y = x.copy()
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


INTERPOLATIONS = {
    "nearest": cv2.INTER_NEAREST,
    "bilinear": cv2.INTER_LINEAR,
    "bicubic": cv2.INTER_CUBIC,
}


def resize(scale, interpolation="bilinear", restore=False):
    """Resize once, optionally resampling back; never return a zero-sized image."""
    if scale <= 0 or interpolation not in INTERPOLATIONS:
        raise ValueError("Skala atau interpolasi resize tidak valid.")

    def f(x):
        h, w = x.shape[:2]
        method = INTERPOLATIONS[interpolation]
        out = cv2.resize(np.ascontiguousarray(x), (max(1, round(w * scale)), max(1, round(h * scale))),
                         interpolation=method)
        return cv2.resize(out, (w, h), interpolation=method) if restore else out
    return f


def crop_center(frac):
    """Remove a fraction of each dimension; this changes carrier coordinates."""
    def f(x):
        h, w = x.shape[:2]
        nh, nw = max(1, round(h * (1 - frac))), max(1, round(w * (1 - frac)))
        top, left = (h - nh) // 2, (w - nw) // 2
        return x[top:top + nh, left:left + nw].copy()
    return f


def erase_area(frac, random_position=False, seed=3):
    """Black rectangle of approximately frac * H * W pixels, without resampling."""
    def f(x):
        h, w = x.shape[:2]
        rh, rw = max(1, round(h * np.sqrt(frac))), max(1, round(w * np.sqrt(frac)))
        if random_position:
            rng = np.random.default_rng(seed)
            top, left = int(rng.integers(h - rh + 1)), int(rng.integers(w - rw + 1))
        else:
            top, left = (h - rh) // 2, (w - rw) // 2
        out = x.copy()
        out[top:top + rh, left:left + rw] = 0
        return out
    return f


def rotate(angle):
    def f(x):
        h, w = x.shape[:2]
        transform = cv2.getRotationMatrix2D(((w - 1) / 2, (h - 1) / 2), angle, 1)
        return cv2.warpAffine(np.ascontiguousarray(x), transform, (w, h),
                              flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_CONSTANT, borderValue=0)
    return f


def translate(pixels):
    def f(x):
        h, w = x.shape[:2]
        transform = np.array([[1, 0, pixels], [0, 1, pixels]], dtype=np.float32)
        return cv2.warpAffine(np.ascontiguousarray(x), transform, (w, h),
                              flags=cv2.INTER_NEAREST, borderMode=cv2.BORDER_CONSTANT, borderValue=0)
    return f


def chain(*operations):
    def f(x):
        for operation in operations:
            x = operation(x)
        return x
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

# Keep the original sixteen entries and their parameters stable.
BASE_NAMES = [name for name, _ in SUITE]
_original = [
    ("Kontrol", "Kontrol", "identitas"),
    ("Kompresi", "Ringan", "quality=95"),
    ("Kompresi", "Sedang", "quality=75"),
    ("Kompresi", "Berat", "quality=50"),
    ("Noise", "Ringan", "sigma=1; seed=1"),
    ("Noise", "Sedang", "sigma=3; seed=1"),
    ("Noise", "Ringan", "p=0.0005; seed=2; per nilai kanal"),
    ("Noise", "Ringan", "p=0.001; seed=2; per nilai kanal"),
    ("Noise", "Sedang", "p=0.005; seed=2; per nilai kanal"),
    ("Noise", "Berat", "p=0.02; seed=2; per nilai kanal"),
    ("Filtering", "Ringan", "kernel=3x3"),
    ("Filtering", "Ringan", "kernel=3x3; sigma=0.8"),
    ("Penghapusan area", "Ringan", "bawah; luas=2%"),
    ("Penghapusan area", "Sedang", "bawah; luas=5%"),
    ("Penghapusan area", "Berat", "bawah; luas=10%"),
    ("Resizing", "Berat", "scale=0.5; turun=area; kembali=bilinear"),
]
DETAILS = {name: dict(kategori=category, tingkat=level, parameter=params)
           for (name, _), (category, level, params) in zip(SUITE, _original)}
ATTACK_SUITE = list(SUITE)


def _add(name, operation, category, level, params):
    ATTACK_SUITE.append((name, operation))
    DETAILS[name] = dict(kategori=category, tingkat=level, parameter=params)


for q in (30, 10):
    _add(f"JPEG Q={q}", jpeg(q), "Kompresi", "Berat", f"quality={q}")
for sigma in (5, 10):
    _add(f"Noise Gauss sigma={sigma}", gauss_noise(sigma), "Noise", "Berat", f"sigma={sigma}; seed=1")
_add("Salt&Pepper 5%", salt_pepper(0.05), "Noise", "Berat", "p=0.05; seed=2; per nilai kanal")
_add("Median filter 5x5", lambda x: cv2.medianBlur(np.ascontiguousarray(x), 5),
     "Filtering", "Berat", "kernel=5x5")
for kernel, sigma, level in ((5, 1.2, "Sedang"), (7, 2.0, "Berat")):
    _add(f"Gaussian blur {kernel}x{kernel}",
         lambda x, k=kernel, s=sigma: cv2.GaussianBlur(np.ascontiguousarray(x), (k, k), s),
         "Filtering", level, f"kernel={kernel}x{kernel}; sigma={sigma}")
_add("Average blur 3x3", lambda x: cv2.blur(np.ascontiguousarray(x), (3, 3)),
     "Filtering", "Ringan", "kernel=3x3")
_add("Average blur 5x5", lambda x: cv2.blur(np.ascontiguousarray(x), (5, 5)),
     "Filtering", "Berat", "kernel=5x5")
_add("Sharpening", lambda x: cv2.filter2D(np.ascontiguousarray(x), -1,
     np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]], dtype=np.float32)),
     "Filtering", "Sedang", "kernel=[0,-1,0;-1,5,-1;0,-1,0]; saturasi uint8")

for scale, level in ((0.9, "Ringan"), (0.75, "Sedang"), (0.5, "Berat"), (0.25, "Berat")):
    for interpolation in INTERPOLATIONS:
        for restore in (False, True):
            suffix = "lalu kembali" if restore else "dimensi berubah"
            _add(f"Resize {scale:.0%} {interpolation}, {suffix}", resize(scale, interpolation, restore),
                 "Resizing", level, f"scale={scale}; interpolasi={interpolation}; kembali={restore}")
for frac, level in ((0.05, "Ringan"), (0.1, "Sedang"), (0.25, "Berat")):
    _add(f"Crop tengah, potong {frac:.0%} tiap dimensi", crop_center(frac),
         "Cropping", level, f"lebar/tinggi tersisa={1-frac}; area tersisa={(1-frac)**2:.4f}")
    for random_position in (False, True):
        position = "acak" if random_position else "tengah"
        _add(f"Penghapusan area {position} {frac:.0%}", erase_area(frac, random_position),
             "Penghapusan area", level, f"luas~{frac}; posisi={position}; seed=3")
for angle, level in ((1, "Ringan"), (5, "Sedang"), (15, "Berat")):
    _add(f"Rotasi {angle} derajat", rotate(angle), "Geometris", level,
         f"sudut={angle}; bilinear; dimensi tetap; batas hitam")
for shift, level in ((1, "Ringan"), (5, "Berat")):
    _add(f"Pergeseran {shift} piksel", translate(shift), "Geometris", level,
         f"dx=dy={shift}; nearest; batas hitam")
_add("Gabungan: resize 50% kembali + JPEG Q=50", chain(resize(0.5, restore=True), jpeg(50)),
     "Gabungan", "Berat", "resize=0.5; bilinear; kembali=True -> JPEG quality=50")
_add("Gabungan: Gaussian 5x5 + JPEG Q=30", chain(
     lambda x: cv2.GaussianBlur(x, (5, 5), 1.2), jpeg(30)),
     "Gabungan", "Berat", "Gaussian kernel=5x5; sigma=1.2 -> JPEG quality=30")
