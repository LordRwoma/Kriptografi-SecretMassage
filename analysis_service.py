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
    attacked = dict(A.ATTACK_SUITE)[name](stego)
    same_shape = stego.shape == attacked.shape
    quality_available = same_shape and min(attacked.shape[:2]) >= 7
    info = info or {}
    row = dict(serangan=name, **A.DETAILS.get(name, {}),
               **quality(stego if quality_available else None, attacked), BER=None,
               dimensi_awal="x".join(map(str, stego.shape)),
               dimensi_akhir="x".join(map(str, attacked.shape)),
               pembanding_kualitas="Stego sebelum vs sesudah serangan",
               status_kualitas="Tersedia" if quality_available else "Dimensi berbeda / citra terlalu kecil",
               status_BER="Referensi penyisipan tidak tersedia", backend=info.get("backend", "auto"),
               metode=("DCT-QIM" if info.get("backend") == "dct" else
                       f"{info.get('mode', 'tidak diketahui')}; k={info.get('k', '?')}"),
               ecc=info.get("ecc"), payload_B=len(expected) if expected is not None else None,
               autentikasi_valid=False, payload_identik=None, SHA256="", keterangan="", status="Gagal dipulihkan")
    if info:
        if not same_shape:
            row["status_BER"] = "Tidak tersedia: dimensi/pemetaan carrier berubah"
        else:
            try:
                row["BER"] = M.ber(info["body_bits"], transport.read_body_bits(attacked, info))
                row["status_BER"] = "Bit body pada posisi referensi, sebelum ECC; bukan BER plaintext"
            except (IndexError, ValueError, KeyError) as exc:
                row["status_BER"] = f"Referensi tidak sesuai: {exc}"
    extract_start = time.perf_counter()
    try:
        out = transport.extract(attacked, password, backend=info.get("backend", "auto"))
        row.update(autentikasi_valid=True, SHA256=hashlib.sha256(out).hexdigest(),
                   payload_identik=(out == expected) if expected is not None else None,
                   keterangan="Payload pulih identik" if expected is not None and out == expected else "Autentikasi GCM valid")
        if expected is not None and out != expected:
            row["keterangan"] = "Payload berbeda dari referensi"
        row["status"] = ("Referensi berbeda" if expected is not None and out != expected else
                         "Pulih identik" if expected is not None else "Autentikasi valid; tanpa referensi")
    except sc.ExtractionError as exc:
        row["keterangan"] = str(exc)
    row["waktu_ekstraksi_ms"] = (time.perf_counter() - extract_start) * 1000
    row["waktu_ms"] = (time.perf_counter() - start) * 1000
    return attacked, row


def attack_csv(rows):
    """Keep exports free of binary payloads, keys and passwords."""
    import pandas as pd
    return pd.DataFrame(rows).to_csv(index=False).encode("utf-8-sig")


def evaluate(cover, stego, password, expected=None, info=None):
    _, row = run_attack(stego, A.SUITE[0][0], password, expected, info)
    row.update(quality(cover, stego))
    row.update(steganalysis(stego))
    row.pop("serangan")
    return row
