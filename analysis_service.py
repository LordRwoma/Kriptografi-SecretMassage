"""Live evaluation on saved stego images, separate from historical experiments."""
import hashlib
import time
import numpy as np

import attacks as A
import image_stego as transport
import metrics as M
import stegocrypt as sc


def quality(cover, stego):
    if cover is None:
        return {"MSE": None, "PSNR_dB": None, "SSIM": None, "nilai_berubah_pct": None}
    if cover.shape != stego.shape:
        raise ValueError("Ukuran dan kanal cover harus sama dengan stego untuk menghitung kualitas.")
    return dict(MSE=M.mse(cover, stego), PSNR_dB=M.psnr(cover, stego), SSIM=M.ssim(cover, stego),
                nilai_berubah_pct=float(100 * np.mean(cover != stego)))


def steganalysis(image):
    return dict(RS_estimasi=M.rs_estimate(image), chi2_p=M.chi2_pvalue(image),
                korelasi_horizontal=M.adjacent_corr(image))


def run_attack(stego, name, password, expected=None, info=None):
    """BER needs reference positions; authentication and payload identity are distinct."""
    start = time.perf_counter()
    attacked = dict(A.SUITE)[name](stego)
    row = dict(serangan=name, **quality(stego, attacked), BER=None,
               autentikasi_valid=False, payload_identik=None, SHA256="", keterangan="")
    if info is not None:
        row["BER"] = M.ber(info["body_bits"], transport.read_body_bits(attacked, info))
    try:
        out = transport.extract(attacked, password, backend=(info or {}).get("backend", "auto"))
        row.update(autentikasi_valid=True, SHA256=hashlib.sha256(out).hexdigest(),
                   payload_identik=(out == expected) if expected is not None else None,
                   keterangan="Payload pulih identik" if expected is not None and out == expected else "Autentikasi GCM valid")
        if expected is not None and out != expected:
            row["keterangan"] = "Payload berbeda dari referensi"
    except sc.ExtractionError as exc:
        row["keterangan"] = str(exc)
    row["waktu_ms"] = (time.perf_counter() - start) * 1000
    return attacked, row


def evaluate(cover, stego, password, expected=None, info=None):
    _, row = run_attack(stego, A.SUITE[0][0], password, expected, info)
    row.update(quality(cover, stego))
    row.update(steganalysis(stego))
    row.pop("serangan")
    return row
