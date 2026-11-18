"""Serialized PNG/LSB and JPEG/DCT steganography with a common AES-GCM core.

JPEG uses four low/mid-frequency luminance coefficients per complete 8x8
block, parity QIM with step 16, and mandatory RS(255,127). Its capacity is
smaller than spatial LSB. No metadata/trailing-byte payload is used.
"""
import io
import numpy as np
from scipy.fft import dctn, idctn

import stegocrypt as sc
from image_io import encode_image, load_image

COEFFICIENTS = ((1, 2), (2, 1), (2, 2), (1, 3))
QIM_STEP = 16.0
JPEG_ECC = 3


def _carrier_shape(shape):
    return (shape[0] // 8 * (shape[1] // 8) * len(COEFFICIENTS),)


def capacity_bytes(shape, output_format="PNG", ecc=0):
    if output_format.upper() in ("JPG", "JPEG"):
        return sc.capacity_bytes(_carrier_shape(shape), JPEG_ECC)
    return sc.capacity_bytes(shape, ecc)


def _transform(image):
    h, w = image.shape[:2]
    bh, bw = h // 8, w // 8
    if not bh or not bw:
        raise ValueError("Mode JPEG memerlukan gambar minimal 8 x 8 piksel.")
    x = image.astype(np.float64)
    y = x if x.ndim == 2 else x @ np.array([0.299, 0.587, 0.114])
    blocks = (y[:bh * 8, :bw * 8] - 128).reshape(bh, 8, bw, 8).transpose(0, 2, 1, 3)
    return dctn(blocks, axes=(-2, -1), norm="ortho"), y


def _values(coeff):
    return np.stack([coeff[..., r, c] for r, c in COEFFICIENTS], axis=-1).reshape(-1)


def _carrier(image):
    coeff, _ = _transform(image)
    bits = (np.rint(_values(coeff) / QIM_STEP).astype(np.int64) & 1).astype(np.uint8)
    return 128 + bits


def _write(image, positions, bits):
    coeff, y = _transform(image)
    values = _values(coeff)
    # The closest point in the lattice with the desired parity, including
    # coefficients whose existing parity already matches (restore margin).
    values[positions] = (2 * np.rint((values[positions] / QIM_STEP - bits) / 2) + bits) * QIM_STEP
    shaped = values.reshape(*coeff.shape[:2], len(COEFFICIENTS))
    for i, (r, c) in enumerate(COEFFICIENTS):
        coeff[..., r, c] = shaped[..., i]
    blocks = idctn(coeff, axes=(-2, -1), norm="ortho") + 128
    new_y = blocks.transpose(0, 2, 1, 3).reshape(coeff.shape[0] * 8, coeff.shape[1] * 8)
    delta = np.zeros_like(y)
    delta[:new_y.shape[0], :new_y.shape[1]] = new_y - y[:new_y.shape[0], :new_y.shape[1]]
    out = image.astype(np.float64) + (delta if image.ndim == 2 else delta[..., None])
    # A block-wide brightness shift changes DC only. It prevents clipping
    # from destroying AC bits in very dark/light regions of photographs.
    bh, bw = coeff.shape[:2]
    roi = out[:bh * 8, :bw * 8]
    if image.ndim == 2:
        rgb_blocks = roi.reshape(bh, 8, bw, 8).transpose(0, 2, 1, 3)
        axes = (-2, -1)
    else:
        rgb_blocks = roi.reshape(bh, 8, bw, 8, 3).transpose(0, 2, 1, 3, 4)
        axes = (-3, -2, -1)
    lower, upper = -rgb_blocks.min(axis=axes), 255 - rgb_blocks.max(axis=axes)
    shift = np.where(lower <= upper, np.minimum(np.maximum(0, lower), upper), (lower + upper) / 2)
    shift_pixels = np.repeat(np.repeat(shift, 8, axis=0), 8, axis=1)
    roi += shift_pixels if image.ndim == 2 else shift_pixels[..., None]
    return np.clip(np.rint(out), 0, 255).astype(np.uint8)


def embed(cover, data, password, output_format="PNG", mode="matrix", ecc=0, compress=False):
    """Return (decoded saved image, info, actual file bytes), after roundtrip verification."""
    fmt = output_format.upper()
    if fmt not in ("PNG", "JPG", "JPEG"):
        raise ValueError("Format keluaran harus PNG atau JPEG.")
    if fmt == "PNG":
        stego, info = sc.embed(cover, data, password, mode=mode, ecc=ecc, compress=compress)
        encoded = encode_image(stego)
        saved = load_image(io.BytesIO(encoded)) if stego.ndim == 3 else _decode_gray(encoded)
        info["backend"] = "lsb"
        verified = sc.extract(saved, password)
    else:
        carrier = _carrier(cover)
        target, info = sc.embed(carrier, data, password, mode="match", ecc=JPEG_ECC, compress=compress)
        positions = np.r_[np.arange(info["header_bits"]), info["sel"]]
        bits = (target[positions] & 1).astype(np.float64)
        candidate = cover
        verified = None
        for _ in range(4):
            candidate = _write(candidate, positions, bits)
            encoded = encode_image(candidate, "JPEG")
            saved = load_image(io.BytesIO(encoded)) if cover.ndim == 3 else _decode_gray(encoded)
            try:
                verified = sc.extract(_carrier(saved), password)
            except sc.ExtractionError:
                candidate = saved
                continue
            break
        if verified is None:
            raise ValueError("Pesan belum pulih setelah penyimpanan JPEG. Gunakan PNG atau gambar sampul lain.")
        info.update(backend="dct", mode="DCT-QIM + ECC 3")
    if verified != data:
        raise ValueError("Verifikasi hasil simpan gagal; gambar tidak diterbitkan.")
    info.update(output_format="PNG" if fmt == "PNG" else "JPEG", verified=True,
                changed=int(np.count_nonzero(saved != cover)))
    return saved, info, encoded


def _decode_gray(encoded):
    from PIL import Image
    with Image.open(io.BytesIO(encoded)) as im:
        return np.array(im.convert("L"))


def extract(image, password, backend="auto"):
    if backend not in ("auto", "lsb", "dct"):
        raise ValueError("Metode ekstraksi tidak dikenal.")
    methods = ("lsb", "dct") if backend == "auto" else (backend,)
    failures = []
    for method in methods:
        try:
            return sc.extract(_carrier(image) if method == "dct" else image, password)
        except (sc.ExtractionError, ValueError) as exc:
            failures.append(f"{'LSB' if method == 'lsb' else 'DCT-QIM'}: {exc}")
    detail = " | ".join(failures)
    raise sc.ExtractionError(
        "Pesan tidak dapat dipulihkan. Pastikan password benar dan gunakan gambar stego asli "
        "yang belum diubah atau dikompres ulang. Password salah dan kerusakan data tidak selalu "
        f"dapat dibedakan. Detail pemeriksaan: {detail}")


def read_body_bits(image, info):
    if info.get("backend") == "dct":
        image = _carrier(image)
    return sc.read_body_bits(image, info)
