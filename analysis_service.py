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
    return dict(
        RS_estimasi=M.rs_estimate(image),
        chi2_p=M.chi2_pvalue(image),
        korelasi_horizontal=M.adjacent_corr(image, "h"),
        korelasi_vertikal=M.adjacent_corr(image, "v"),
        korelasi_diagonal=M.adjacent_corr(image, "d"),
    )


def make_benchmark_payload(n: int) -> bytes:
    words = (
        "keamanan data kriptografi steganografi citra kunci enkripsi pesan rahasia "
        "sistem algoritma blok sandi digital integritas autentikasi jaringan protokol "
        "payload piksel warna kanal saluran bit byte hash tanda tangan sembunyi ekstraksi"
    ).split()
    rng = np.random.default_rng(n)
    out, length = [], 0
    while length < n:
        w = words[rng.integers(len(words))] + " "
        out.append(w)
        length += len(w)
    return "".join(out).encode("utf-8")[:n]


def compute_10_payload_sizes(capacity: int) -> list[int]:
    if capacity < 16:
        return [capacity] if capacity > 0 else []
    if capacity >= 1000:
        fractions = [0.0002, 0.0008, 0.003, 0.01, 0.04, 0.10, 0.25, 0.50, 0.75, 1.0]
        sizes = [max(16, int(round(f * capacity))) for f in fractions]
    else:
        sizes = np.geomspace(16, capacity, num=10).round().astype(int).tolist()

    unique_sizes = []
    for s in sizes:
        s = min(max(16, s), capacity)
        if not unique_sizes or s > unique_sizes[-1]:
            unique_sizes.append(s)

    while len(unique_sizes) < 10 and len(unique_sizes) < capacity - 16 + 1:
        gaps = [(unique_sizes[i + 1] - unique_sizes[i], i) for i in range(len(unique_sizes) - 1)]
        gaps.sort(reverse=True)
        max_gap, idx = gaps[0]
        if max_gap <= 1:
            break
        mid = (unique_sizes[idx] + unique_sizes[idx + 1]) // 2
        unique_sizes.insert(idx + 1, mid)

    if unique_sizes and unique_sizes[-1] != capacity:
        unique_sizes[-1] = capacity

    return unique_sizes


def benchmark_10_payloads(
    cover: np.ndarray,
    password: str,
    output_format: str = "PNG",
    mode: str = "matrix",
    ecc: int = 0,
    compress: bool = False,
    progress_callback=None,
) -> list[dict]:
    """Run full 10-payload benchmark on the given cover image."""
    cap = transport.capacity_bytes(cover.shape, output_format, ecc)
    if cap < 16:
        raise ValueError(
            f"Kapasitas gambar ({cap} byte) terlalu kecil untuk pengujian 10 payload (minimal 16 byte)."
        )
    sizes = compute_10_payload_sizes(cap)
    if not sizes:
        raise ValueError("Gagal menghitung ukuran payload untuk pengujian.")

    rows = []
    total = len(sizes)
    for i, sz in enumerate(sizes):
        payload = make_benchmark_payload(sz)
        t_start_emb = time.perf_counter()
        saved, info, _ = transport.embed(
            cover,
            payload,
            password,
            output_format=output_format,
            mode=mode,
            ecc=ecc,
            compress=compress,
        )
        t_emb_ms = (time.perf_counter() - t_start_emb) * 1000

        t_start_ext = time.perf_counter()
        extracted = transport.extract(saved, password, backend=info.get("backend", "auto"))
        t_ext_ms = (time.perf_counter() - t_start_ext) * 1000

        identical = extracted == payload
        ber_val = M.ber(info["body_bits"], transport.read_body_bits(saved, info))
        psnr_val = M.psnr(cover, saved)
        ssim_val = M.ssim(cover, saved)
        mse_val = M.mse(cover, saved)
        changed_pct = float(100 * np.mean(cover != saved))
        bpp_val = float(8 * len(payload) / (cover.shape[0] * cover.shape[1]))

        row = {
            "No": i + 1,
            "Payload (B)": len(payload),
            "% Kapasitas": round(100 * len(payload) / max(cap, 1), 2),
            "bpp": round(bpp_val, 4),
            "MSE": round(mse_val, 6),
            "PSNR (dB)": round(psnr_val, 2),
            "SSIM": round(ssim_val, 5),
            "Piksel Berubah (%)": round(changed_pct, 3),
            "BER": round(ber_val, 6),
            "Hash Cocok": "Ya" if identical else "Tidak",
            "Waktu Embed (ms)": round(t_emb_ms, 1),
            "Waktu Extract (ms)": round(t_ext_ms, 1),
            "k Hamming": info.get("k", 1),
        }
        rows.append(row)
        if progress_callback:
            progress_callback((i + 1) / total, row)

    return rows


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
    return pd.DataFrame(rows).drop(columns=["tingkat"], errors="ignore").to_csv(index=False).encode("utf-8-sig")


def evaluate(cover, stego, password, expected=None, info=None):
    _, row = run_attack(stego, A.SUITE[0][0], password, expected, info)
    row.update(quality(cover, stego))
    row.update(steganalysis(stego))
    row.pop("serangan")
    return row
