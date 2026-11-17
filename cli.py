#!/usr/bin/env python3
"""
CLI StegoCrypt-X v2
  python cli.py embed   --cover foto.png --payload rahasia.txt --out stego.png [--password KUNCI] [--mode matrix|match|replace] [--ecc 0-3] [--compress]
  python cli.py extract --stego stego.png --out hasil.txt [--password KUNCI]
  python cli.py capacity --cover foto.png
  python cli.py analyze --cover foto.png --stego stego.png        # PSNR/SSIM/MSE + RS + chi-kuadrat
  python cli.py demo                                              # demo end-to-end otomatis (untuk presentasi)
Password: jika --password dihilangkan, dibaca dari env STEGO_PASSWORD atau diminta lewat prompt (tidak tampil di riwayat shell).
Simpan stego sebagai PNG (lossless). JPEG akan merusak LSB.
"""
import argparse, getpass, hashlib, os, sys, time
import numpy as np
from PIL import Image
import stegocrypt as sc, metrics as M

G, R, Y, B, X = "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[0m"
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    G = R = Y = B = X = ""


def load(p): return np.array(Image.open(p).convert("RGB"))
def save(a, p): Image.fromarray(a).save(p, format="PNG")
def pw(a): return a.password or os.environ.get("STEGO_PASSWORD") or getpass.getpass("Password: ")
def ok(t): return f"{G}✔ {t}{X}"
def bad(t): return f"{R}✘ {t}{X}"


def cmd_embed(a):
    cov, data = load(a.cover), open(a.payload, "rb").read()
    t = time.perf_counter()
    try:
        st, info = sc.embed(cov, data, pw(a), mode=a.mode, ecc=a.ecc, compress=a.compress)
    except ValueError as e:
        sys.exit(bad(str(e)))
    dt = time.perf_counter() - t; save(st, a.out)
    print(ok(f"{len(data)} B disisipkan ({100 * len(data) / sc.capacity_bytes(cov.shape, a.ecc):.2f}% kapasitas) dalam {dt * 1000:.0f} ms"))
    print(f"   mode={a.mode}  k={info['k']}  ECC={a.ecc}  zlib={info['compressed']}  nilai berubah={100 * info['changed'] / cov.size:.3f}%")
    print(f"   PSNR={M.psnr(cov, st):.2f} dB  SSIM={M.ssim(cov, st):.5f}  MSE={M.mse(cov, st):.4f}  -> {a.out}")


def cmd_extract(a):
    try:
        data = sc.extract(load(a.stego), pw(a))
    except sc.ExtractionError as ex:
        sys.exit(bad(f"GAGAL: {ex}"))
    open(a.out, "wb").write(data)
    print(ok(f"{len(data)} B diekstrak -> {a.out}  (SHA-256 {hashlib.sha256(data).hexdigest()[:16]}…)"))


def cmd_capacity(a):
    im = load(a.cover); h, w = im.shape[:2]
    print(f"{w}x{h} px  ->  default {sc.capacity_bytes(im.shape)} B | ECC1 {sc.capacity_bytes(im.shape, 1)} B | "
          f"ECC2 {sc.capacity_bytes(im.shape, 2)} B | ECC3 {sc.capacity_bytes(im.shape, 3)} B  (data acak/terkompresi)")


def cmd_analyze(a):
    c, s = load(a.cover), load(a.stego)
    print(f"PSNR={M.psnr(c, s):.2f} dB  SSIM={M.ssim(c, s):.5f}  MSE={M.mse(c, s):.4f}  nilai berubah={100 * np.mean(c != s):.3f}%")
    print(f"RS estimasi  cover={M.rs_estimate(c):.4f}  stego={M.rs_estimate(s):.4f}   |   chi² p  cover={M.chi2_pvalue(c):.3g}  stego={M.chi2_pvalue(s):.3g}")


def demo(a):
    from skimage import data as sd
    import attacks as A
    cov = sd.astronaut(); P = "demo-pass-2026"
    msg = ("Pesan rahasia UAS Kriptografi & Keamanan Data — AES-256-GCM + LSB matching + matrix embedding. " * 30).encode()
    print(f"{B}═══ DEMO StegoCrypt-X v2 ═══{X}")
    print(f"1) Cover 512×512 RGB | kapasitas default {sc.capacity_bytes(cov.shape)} B | ECC3 {sc.capacity_bytes(cov.shape, 3)} B")
    t = time.perf_counter(); st, info = sc.embed(cov, msg, P); dt = time.perf_counter() - t; save(st, "demo_stego.png")
    print(f"2) Embed {len(msg)} B ({dt * 1000:.0f} ms): k={info['k']}  PSNR={M.psnr(cov, st):.2f} dB  SSIM={M.ssim(cov, st):.5f}  berubah={100 * info['changed'] / cov.size:.3f}%")
    out = sc.extract(np.array(Image.open("demo_stego.png")), P)
    print("3) Extract (PNG dari disk, password benar):", ok("COCOK, hash identik") if out == msg else bad("BEDA"))
    try: sc.extract(st, "password-salah"); print("4)", bad("password salah DITERIMA?!"))
    except sc.ExtractionError as ex: print("4) Password salah  :", ok(f"DITOLAK → {ex}"))
    t2 = st.reshape(-1).copy(); t2[info["sel"][500]] ^= 1
    try: sc.extract(t2.reshape(st.shape), P); print("5)", bad("tamper tidak terdeteksi?!"))
    except sc.ExtractionError as ex: print("5) Tamper 1 bit LSB:", ok(f"TERDETEKSI → {ex}"))
    sp = A.salt_pepper(0.01)
    try: sc.extract(sp(st), P); print("6) Salt&Pepper 1% (mode default):", bad("lolos?"))
    except sc.ExtractionError: print("6) Salt&Pepper 1% pada mode default:", f"{Y}gagal (LSB rapuh — diharapkan){X}")
    stR, _ = sc.embed(cov, msg[:1500], P, ecc=3)
    print("7) Mode ECC3 + Salt&Pepper 1%      :", ok("PULIH utuh (Reed-Solomon)") if sc.extract(sp(stR), P) == msg[:1500] else bad("gagal"))
    print(f"{B}File: demo_stego.png{X}  — jalankan `streamlit run app.py` untuk demo visual interaktif.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("embed"); e.add_argument("--cover", required=True); e.add_argument("--payload", required=True); e.add_argument("--out", required=True)
    e.add_argument("--password"); e.add_argument("--mode", default="matrix", choices=sc.MODES); e.add_argument("--ecc", type=int, default=0, choices=[0, 1, 2, 3]); e.add_argument("--compress", action="store_true")
    x = sub.add_parser("extract"); x.add_argument("--stego", required=True); x.add_argument("--out", required=True); x.add_argument("--password")
    c = sub.add_parser("capacity"); c.add_argument("--cover", required=True)
    n = sub.add_parser("analyze"); n.add_argument("--cover", required=True); n.add_argument("--stego", required=True)
    sub.add_parser("demo")
    a = ap.parse_args()
    {"embed": cmd_embed, "extract": cmd_extract, "capacity": cmd_capacity, "analyze": cmd_analyze, "demo": demo}[a.cmd](a)


if __name__ == "__main__":
    main()
