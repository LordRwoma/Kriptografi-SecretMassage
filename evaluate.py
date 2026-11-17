"""Evaluasi lengkap StegoCrypt-X v2  ->  results/*.csv  +  figures/*.png
Jalankan:  python evaluate.py            (± 6-8 menit)      python evaluate.py --quick   (uji cepat)
"""
import argparse, hashlib, io, json, os, sys, time, tracemalloc, zlib
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from PIL import Image
from skimage import data
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import stegocrypt as sc, metrics as M, attacks as A, steganalysis as SA

ap = argparse.ArgumentParser(); ap.add_argument("--quick", action="store_true"); args = ap.parse_args()
PASSWORD = "K3amanan-Data#2026"
SIZES = [16, 64, 256, 1024, 4096, 10240, 24576, 49152, 73728, 98256]       # 10 payload (byte); terakhir = kapasitas penuh
REPEATS = 1 if args.quick else 3
os.makedirs("results", exist_ok=True); os.makedirs("figures", exist_ok=True)
plt.rcParams.update({"figure.dpi": 130, "axes.grid": True, "grid.alpha": .3, "axes.spines.top": False,
                     "axes.spines.right": False, "font.size": 9, "savefig.bbox": "tight"})
C1, C2, C3, C4, C5, GR = "#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c", "#6b7280"
WORDS = ("keamanan data kriptografi steganografi citra kunci enkripsi pesan rahasia sistem algoritma blok sandi digital "
         "integritas autentikasi jaringan protokol payload piksel warna kanal saluran bit byte hash tanda tangan "
         "sembunyi ekstraksi").split()


def make_payload(n):
    """Teks bergaya Indonesia (entropi rendah) agar efek enkripsi terlihat jelas; deterministik."""
    rng = np.random.default_rng(n); out, L = [], 0
    while L < n:
        w = WORDS[rng.integers(len(WORDS))] + " "; out.append(w); L += len(w)
    return "".join(out).encode()[:n]


def png_bytes(a):
    b = io.BytesIO(); Image.fromarray(a).save(b, format="PNG", optimize=False); return b.getvalue()


def png_roundtrip(a):
    return np.array(Image.open(io.BytesIO(png_bytes(a))))


def logx(ax, lab=True):
    ax.set_xscale("log")
    if lab: ax.set_xlabel("Ukuran payload (byte, skala log)")


def save(fig, name):
    fig.savefig(f"figures/{name}.png"); plt.close(fig)


cover = data.astronaut(); H, W = cover.shape[:2]
print(f"Cover {cover.shape}, kapasitas maks = {sc.capacity_bytes(cover.shape)} B (ECC1/2/3: "
      f"{[sc.capacity_bytes(cover.shape, e) for e in (1, 2, 3)]})")

# =============================================================== 1. UJI 10 PAYLOAD (cover utama)
print("\n[1] Uji 10 payload"); rows, stegos = [], {}
base_rs, base_chi = M.rs_estimate(cover), M.chi2_pvalue(cover)
t = time.perf_counter(); [sc.kdf_time_probe() for _ in range(5)]; kdf_ms = 1000 * (time.perf_counter() - t) / 5
png_cov = len(png_bytes(cover))
for n in SIZES:
    pl = make_payload(n); h_in = hashlib.sha256(pl).hexdigest(); te, tx = [], []
    for _ in range(REPEATS):
        t = time.perf_counter(); st, info = sc.embed(cover, pl, PASSWORD); te.append(time.perf_counter() - t)
        st_png = png_roundtrip(st)
        t = time.perf_counter(); out = sc.extract(st_png, PASSWORD); tx.append(time.perf_counter() - t)
    st_c, info_c = sc.embed(cover, pl, PASSWORD, mode="match")                # pembanding: LSB matching biasa (k=1)
    tracemalloc.start(); sc.embed(cover, pl, PASSWORD); pe = tracemalloc.get_traced_memory()[1]; tracemalloc.stop()
    tracemalloc.start(); sc.extract(st_png, PASSWORD); px = tracemalloc.get_traced_memory()[1]; tracemalloc.stop()
    stegos[n] = st
    ct = info["ciphertext"]; ctb = np.unpackbits(np.frombuffer(ct, np.uint8))
    rows.append(dict(
        payload_B=n, payload_bit=n * 8, k_matrix=info["k"], ukuran_blob_B=info["blob_len"] + sc.HEADER_BYTES,
        ekspansi_B=info["blob_len"] + sc.HEADER_BYTES - n, pct_kapasitas=100 * n / sc.capacity_bytes(cover.shape),
        bpp=8 * n / (H * W), bits_per_channel=8 * n / cover.size,
        MSE=M.mse(cover, st), PSNR_dB=M.psnr(cover, st), SSIM=M.ssim(cover, st),
        MSE_match=M.mse(cover, st_c), PSNR_match_dB=M.psnr(cover, st_c), SSIM_match=M.ssim(cover, st_c),
        gain_PSNR_dB=M.psnr(cover, st) - M.psnr(cover, st_c),
        nilai_berubah_pct=100 * info["changed"] / cover.size, nilai_berubah_match_pct=100 * info_c["changed"] / cover.size,
        efisiensi_bit_per_ubah=info["efficiency"],
        BER=M.ber(info["body_bits"], sc.read_body_bits(st_png, info)), hash_cocok=(hashlib.sha256(out).hexdigest() == h_in),
        H_plaintext=M.entropy_bytes(pl), H_ciphertext=M.entropy_bytes(ct),
        monobit_p=M.nist_monobit(ctb), runs_p=M.nist_runs(ctb), chi2_byte_p=M.chi2_uniform_bytes(ct),
        korelasi_cover=M.adjacent_corr(cover), korelasi_stego=M.adjacent_corr(st),
        RS_est=M.rs_estimate(st), RS_cover=base_rs, chi2_p=M.chi2_pvalue(st), chi2_p_cover=base_chi,
        png_cover_KB=png_cov / 1024, png_stego_KB=len(png_bytes(st)) / 1024,
        t_embed_ms=1000 * np.mean(te), t_extract_ms=1000 * np.mean(tx), t_kdf_ms=kdf_ms,
        mem_embed_MB=pe / 2 ** 20, mem_extract_MB=px / 2 ** 20))
    r = rows[-1]
    print(f"  {n:>6} B  k={r['k_matrix']:>2}  PSNR={r['PSNR_dB']:.2f} (match {r['PSNR_match_dB']:.2f})  SSIM={r['SSIM']:.5f}  "
          f"BER={r['BER']:.0f}  hash={r['hash_cocok']}", flush=True)
df = pd.DataFrame(rows); df.to_csv("results/payload_results.csv", index=False)
assert df.hash_cocok.all() and (df.BER == 0).all()

# =============================================================== 2. MULTI-COVER (10 payload x cover)
print("\n[2] Multi-cover"); covers = {"astronaut 512×512 RGB": data.astronaut(), "coffee 400×600 RGB": data.coffee(),
    "chelsea 300×451 RGB": data.chelsea(), "rocket 427×640 RGB": data.rocket(),
    "immunohisto 512×512 RGB": data.immunohistochemistry(), "hubble 872×1000 RGB": data.hubble_deep_field(),
    "camera 512×512 Gray": data.camera(), "moon 512×512 Gray": data.moon()}
mrows = []
for nm, c in covers.items():
    cap = sc.capacity_bytes(c.shape)
    for n in [s for s in SIZES if s <= cap] + ([cap] if cap not in SIZES else []):
        pl = make_payload(n); st, info = sc.embed(c, pl, PASSWORD); ok = sc.extract(png_roundtrip(st), PASSWORD) == pl
        mrows.append(dict(cover=nm, payload_B=n, pct_kapasitas=100 * n / cap, k=info["k"], PSNR_dB=M.psnr(c, st),
                          SSIM=M.ssim(c, st), hash_cocok=ok))
    print(f"  {nm}: cap={cap} B", flush=True)
mdf = pd.DataFrame(mrows); mdf.to_csv("results/multicover.csv", index=False); assert mdf.hash_cocok.all()

# =============================================================== 3. KAPASITAS
print("\n[3] Kapasitas")
crow = []
for nm, c in covers.items():
    cap = sc.capacity_bytes(c.shape); pix = c.shape[0] * c.shape[1]
    lo, hi = 1, cap * 20                                           # kapasitas efektif untuk teks + kompresi zlib
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(zlib.compress(make_payload(mid), 9)) + sc.TAG_LEN <= cap + sc.TAG_LEN: lo = mid
        else: hi = mid - 1
    pl = make_payload(lo); st, _ = sc.embed(c, pl, PASSWORD, compress=True); ok_c = sc.extract(st, PASSWORD) == pl
    stf, _ = sc.embed(c, make_payload(cap), PASSWORD); ok_f = sc.extract(stf, PASSWORD) == make_payload(cap)
    crow.append(dict(cover=nm, piksel=pix, kapasitas_B=cap, kapasitas_bpp=8 * cap / pix,
                     kapasitas_ECC1_B=sc.capacity_bytes(c.shape, 1), kapasitas_ECC2_B=sc.capacity_bytes(c.shape, 2),
                     kapasitas_ECC3_B=sc.capacity_bytes(c.shape, 3), teks_efektif_kompresi_B=lo, faktor_kompresi=lo / cap,
                     PSNR_100pct=M.psnr(c, stf), SSIM_100pct=M.ssim(c, stf), ekstraksi_100pct_ok=ok_f, ekstraksi_kompresi_ok=ok_c))
cdf = pd.DataFrame(crow); cdf.to_csv("results/capacity.csv", index=False); assert cdf.ekstraksi_100pct_ok.all() and cdf.ekstraksi_kompresi_ok.all()

# =============================================================== 4. STEGANALISIS (RS + chi2 pada citra utama; ML pada patch)
print("\n[4] Steganalisis"); srows = []
for name, kw in SA.SCHEMES.items():
    for n in SIZES:
        rng = np.random.default_rng(n); alpha = n * 8 / (cover.size - sc.HEADER_BITS)
        st, k = SA.embed_random(cover, min(alpha, 1.0), rng=rng, **kw)
        srows.append(dict(skema=name, payload_B=n, rasio_true=alpha, k=k, RS_est=M.rs_estimate(st), chi2_p=M.chi2_pvalue(st),
                          PSNR=M.psnr(cover, st), SSIM=M.ssim(cover, st), berubah_pct=100 * np.mean(st != cover)))
sdf = pd.DataFrame(srows); sdf.to_csv("results/steganalysis_ablation.csv", index=False)
ml_alphas = (0.1, 0.25, 0.5, 1.0) if args.quick else (0.05, 0.1, 0.25, 0.5, 1.0)
mlrows, roc = SA.run_ml(alphas=ml_alphas)
mldf = pd.DataFrame(mlrows); mldf.to_csv("results/ml_steganalysis.csv", index=False)

# =============================================================== 5. ROBUSTNESS (plain vs ECC)
print("\n[5] Robustness"); pl = make_payload(1024); rrows = []
profiles = {"Default (tanpa ECC)": 0, "ECC level 2 (RS 255,191)": 2, "ECC level 3 (RS 255,127)": 3}
enc = {p: sc.embed(cover, pl, PASSWORD, ecc=e) for p, e in profiles.items()}
for aname, fn in A.SUITE:
    for pname, e in profiles.items():
        st, info = enc[pname]; att = fn(st)
        try: ok = sc.extract(att, PASSWORD) == pl
        except sc.ExtractionError: ok = False
        rrows.append(dict(serangan=aname, profil=pname, PSNR_vs_stego=M.psnr(st, att),
                          BER=M.ber(info["body_bits"], sc.read_body_bits(att, info)), ekstraksi_berhasil=ok))
    print(f"  {aname:<30} " + " ".join("OK " if r["ekstraksi_berhasil"] else "xx " for r in rrows[-3:]), flush=True)
rdf = pd.DataFrame(rrows); rdf.to_csv("results/robustness.csv", index=False)

# =============================================================== 6. KEAMANAN
print("\n[6] Keamanan")
pl = make_payload(2048); st, info = sc.embed(cover, pl, PASSWORD)
N_WRONG, N_TAM = 50, 30
wrong = 0
for i in range(N_WRONG):
    try: sc.extract(st, f"tebakan-{i}"); wrong += 1
    except sc.ExtractionError: pass
rng = np.random.default_rng(7); tam_det = 0
for _ in range(N_TAM):                                          # 1 bit LSB acak pada posisi body diflip
    t2 = st.reshape(-1).copy(); t2[rng.choice(info["sel"])] ^= 1
    try:
        sc.extract(t2.reshape(st.shape), PASSWORD)
    except sc.ExtractionError: tam_det += 1
st3, info3 = sc.embed(cover, pl, PASSWORD, ecc=3)               # ECC: 1 flip dikoreksi; banjir flip ditolak (tak pernah data salah)
fix1 = silent_bad = rej_many = 0
for _ in range(N_TAM):
    t2 = st3.reshape(-1).copy(); t2[rng.choice(info3["sel"])] ^= 1
    try: fix1 += sc.extract(t2.reshape(st3.shape), PASSWORD) == pl
    except sc.ExtractionError: pass
for _ in range(N_TAM):
    t2 = st3.reshape(-1).copy(); m = rng.random(t2.size) < 0.20; t2[m] ^= 1      # 20% LSB rusak >> kapasitas koreksi
    try:
        out = sc.extract(t2.reshape(st3.shape), PASSWORD); silent_bad += out != pl
    except sc.ExtractionError: rej_many += 1
# avalanche kunci: 1 karakter password berbeda -> ciphertext
salt, nonce = os.urandom(16), os.urandom(12); fr = []
for i in range(200):
    pw = f"password-{i}-xyz"; pw2 = pw[:-1] + chr(ord(pw[-1]) ^ 1)
    ek1, ek2 = sc._derive(pw, salt)[0], sc._derive(pw2, salt)[0] if i < 20 else None
    if ek2 is None: break
    c1, c2 = AESGCM(ek1).encrypt(nonce, make_payload(256), None), AESGCM(ek2).encrypt(nonce, make_payload(256), None)
    fr.append(np.unpackbits(np.frombuffer(bytes(a ^ b for a, b in zip(c1, c2)), np.uint8)).mean())
ek = sc._derive("pw", salt)[0]; p0 = make_payload(256); p1 = bytearray(p0); p1[10] ^= 1
c0, c1 = AESGCM(ek).encrypt(nonce, p0, None), AESGCM(ek).encrypt(nonce, bytes(p1), None)
dif = lambda a, b: float(np.unpackbits(np.frombuffer(bytes(x ^ y for x, y in zip(a, b)), np.uint8)).mean())
gps = 1000 / kdf_ms
spaces = {"PIN 6 digit": 10 ** 6, "8 huruf kecil": 26 ** 8, "8 alfanumerik": 62 ** 8, "12 alfanumerik": 62 ** 12,
          "Passphrase 5 kata (diceware)": 7776 ** 5, "Passphrase 6 kata (diceware)": 7776 ** 6, "Kunci AES-256 (acak)": 2 ** 256}
brute = pd.DataFrame([dict(ruang_password=k, kombinasi=f"{v:.2e}", waktu_1_core_tahun=f"{v / 2 / gps / 3.15576e7:.2e}",
                           waktu_1juta_core_tahun=f"{v / 2 / gps / 1e6 / 3.15576e7:.2e}") for k, v in spaces.items()])
brute.to_csv("results/bruteforce.csv", index=False)
sec = dict(wrong_password_ditolak=f"{N_WRONG - wrong}/{N_WRONG}", tamper_1bit_terdeteksi_tanpa_ECC=f"{tam_det}/{N_TAM}",
           tamper_1bit_dikoreksi_ECC3=f"{int(fix1)}/{N_TAM}", rusak_20pct_ECC3_ditolak=f"{rej_many}/{N_TAM}",
           rusak_20pct_ECC3_data_salah_diterima=int(silent_bad), kdf_ms_per_tebakan=kdf_ms, tebakan_per_detik_1core=gps,
           scrypt_N=sc.SCRYPT_N, avalanche_kunci_ct_bit_beda=float(np.mean(fr)), avalanche_kunci_std=float(np.std(fr)),
           bitflip_plaintext_ct_bit_beda=dif(c0[:-16], c1[:-16]), bitflip_plaintext_tag_bit_beda=dif(c0[-16:], c1[-16:]),
           rs_cover=base_rs)
print(" ", sec)

# ---- ketergantungan terhadap jenis payload
types = {"Teks Indonesia": make_payload(4096), "JSON": json.dumps([{"id": i, "nama": f"user{i}", "aktif": i % 2 == 0} for i in range(150)]).encode()[:4096],
         "CSV": ("\n".join(f"{i},{i*i},{i%7}" for i in range(900))).encode()[:4096], "Kode Python": open("stegocrypt.py", "rb").read()[:4096],
         "Biner acak": os.urandom(4096), "Semua nol": bytes(4096),
         "PNG (gambar)": png_bytes(data.astronaut()[180:236, 180:236])}
trows = []
for nm, pl in types.items():
    stt, inf = sc.embed(cover, pl, PASSWORD); ok = sc.extract(png_roundtrip(stt), PASSWORD) == pl
    trows.append(dict(jenis=nm, ukuran_B=len(pl), H_plaintext=M.entropy_bytes(pl), H_ciphertext=M.entropy_bytes(inf["ciphertext"]),
                      chi2_byte_p=M.chi2_uniform_bytes(inf["ciphertext"]), PSNR_dB=M.psnr(cover, stt), hash_cocok=ok))
tdf = pd.DataFrame(trows); tdf.to_csv("results/payload_types.csv", index=False)
json.dump(dict(sec=sec, cover_shape=list(cover.shape), cap=sc.capacity_bytes(cover.shape), rs_cover=base_rs),
          open("results/summary.json", "w"), indent=1, default=float)

# =============================================================== FIGURES
print("\n[7] Gambar")
x = df.payload_B
# fig0 arsitektur
fig, ax = plt.subplots(figsize=(13, 6.2)); ax.axis("off"); ax.set_xlim(0, 13); ax.set_ylim(0, 6.2)
def box(x0, y0, w, h, txt, col, fs=8.5):
    ax.add_patch(FancyBboxPatch((x0, y0), w, h, boxstyle="round,pad=0.03,rounding_size=0.12", fc=col, ec="#334155", lw=1.1))
    ax.text(x0 + w / 2, y0 + h / 2, txt, ha="center", va="center", fontsize=fs)
def arr(x0, y0, x1, y1, st="-|>"): ax.annotate("", xy=(x1, y1), xytext=(x0, y0), arrowprops=dict(arrowstyle=st, lw=1.2, color="#334155"))
ax.text(0.05, 5.95, "PENGIRIM (embed)", fontsize=11, weight="bold", color=C1); ax.text(0.05, 1.75, "PENERIMA (extract)", fontsize=11, weight="bold", color=C3)
Y1, Y3 = 4.7, 0.45
box(0.05, Y1, 1.6, .95, "Payload\n(+ zlib opsional)", "#dbeafe"); box(2.05, Y1, 1.8, .95, "AES-256-GCM\nnonce acak\nAAD = header", "#fde68a")
box(4.25, Y1, 1.7, .95, "Reed-Solomon\n(opsional, ECC 0–3)", "#fed7aa"); box(6.35, Y1, 2.2, .95, "Pilih k Hamming\nmatrix embedding\n+ LSB matching ±1", "#bbf7d0")
box(8.95, Y1, 1.8, .95, "Posisi acak berkunci\nPRF = AES-CTR", "#e9d5ff"); box(11.15, Y1, 1.8, .95, "Stego-image\n(PNG lossless)", "#fecaca")
for a_, b_ in [(1.65, 2.05), (3.85, 4.25), (5.95, 6.35), (8.55, 8.95), (10.75, 11.15)]: arr(a_, Y1 + .47, b_, Y1 + .47)
box(2.05, 2.55, 8.7, .85, "password  →  scrypt (N=2¹⁵, 32 MiB)  →  HKDF  →  { kunci AES-256  |  kunci PRF posisi  |  mask header }", "#f1f5f9", 9)
arr(2.95, 3.4, 2.95, Y1); arr(9.85, 3.4, 9.85, Y1)
box(11.15, Y3, 1.8, .95, "Baca header\nsalt|nonce|ctrl⊕mask", "#e2e8f0"); box(8.95, Y3, 1.8, .95, "Baca LSB @ posisi\n+ decode Hamming", "#bbf7d0")
box(6.35, Y3, 2.2, .95, "RS decode\n(koreksi error)", "#fed7aa"); box(2.05, Y3, 3.9, .95, "Verifikasi tag GCM (deteksi tamper)\n+ dekripsi + (zlib)", "#fde68a"); box(0.05, Y3, 1.6, .95, "Payload asli ✔\nhash cocok", "#bbf7d0")
arr(12.05, Y1, 12.05, Y3 + .95); arr(11.15, Y3 + .47, 10.75, Y3 + .47); arr(8.95, Y3 + .47, 8.55, Y3 + .47); arr(6.35, Y3 + .47, 5.95, Y3 + .47); arr(2.05, Y3 + .47, 1.65, Y3 + .47)
arr(2.95, 2.55, 2.95, Y3 + .95); arr(9.85, 2.55, 9.85, Y3 + .95)
ax.text(12.15, 3.0, "256 nilai kanal\npertama", fontsize=7.5, color=GR)
ax.set_title("Arsitektur StegoCrypt-X v2: Kriptografi (AES-256-GCM) + Steganografi (LSB matching + matrix embedding)", fontsize=10.5)
save(fig, "fig0_arsitektur")
# fig1 kualitas
fig, ax = plt.subplots(1, 3, figsize=(13, 3.6))
ax[0].plot(x, df.PSNR_dB, "o-", c=C1, label="Matrix embedding (diusulkan)"); ax[0].plot(x, df.PSNR_match_dB, "s--", c=C2, label="LSB matching biasa")
ax[0].axhline(40, ls="--", c="gray", lw=.8); ax[0].text(x.iloc[0], 41, "batas 'tak terlihat' ≈ 40 dB", fontsize=7); ax[0].set_ylabel("PSNR (dB)"); ax[0].set_title("PSNR vs payload"); ax[0].legend(fontsize=7)
ax[1].plot(x, df.SSIM, "o-", c=C3, label="Matrix embedding"); ax[1].plot(x, df.SSIM_match, "s--", c=C2, label="LSB matching biasa"); ax[1].set_ylabel("SSIM"); ax[1].set_title("SSIM vs payload"); ax[1].legend(fontsize=7)
ax[2].plot(x, df.MSE, "o-", c=C1, label="Matrix embedding"); ax[2].plot(x, df.MSE_match, "s--", c=C2, label="LSB matching biasa"); ax[2].set_yscale("log"); ax[2].set_ylabel("MSE"); ax[2].set_title("MSE vs payload"); ax[2].legend(fontsize=7)
for a in ax: logx(a)
fig.tight_layout(); save(fig, "fig1_kualitas")
# fig2 performa
fig, ax = plt.subplots(1, 3, figsize=(13, 3.6))
ax[0].plot(x, df.t_embed_ms, "o-", c=C1, label="Embed (enkripsi+sisip)"); ax[0].plot(x, df.t_extract_ms, "s-", c=C2, label="Extract (ekstrak+dekripsi)")
ax[0].axhline(kdf_ms, ls="--", c="gray", lw=.8, label=f"biaya KDF scrypt ≈ {kdf_ms:.0f} ms"); ax[0].legend(fontsize=7); ax[0].set_ylabel("Waktu (ms)"); ax[0].set_title("Waktu proses")
ax[1].plot(x, df.mem_embed_MB, "o-", c=C1, label="Embed"); ax[1].plot(x, df.mem_extract_MB, "s-", c=C2, label="Extract"); ax[1].set_ylabel("Peak memori Python/NumPy (MB)"); ax[1].set_title("Penggunaan memori"); ax[1].legend(fontsize=7)
ax[2].bar(range(len(x)), df.ekspansi_B, color=C4); ax[2].set_xticks(range(len(x))); ax[2].set_xticklabels(x, rotation=45); ax[2].set_ylabel("Overhead (byte)")
ax[2].set_xlabel("Payload (byte)"); ax[2].set_title("Ekspansi ukuran = 32 B header + 16 B tag")
for a in ax[:2]: logx(a)
fig.tight_layout(); save(fig, "fig2_performa")
# fig3 visual
big = stegos[SIZES[4]]; full = stegos[SIZES[-1]]; d4 = np.abs(big.astype(int) - cover.astype(int)); d9 = np.abs(full.astype(int) - cover.astype(int))
fig, ax = plt.subplots(2, 4, figsize=(15, 7.6))
ax[0, 0].imshow(cover); ax[0, 0].set_title("Cover asli"); ax[0, 1].imshow(big); ax[0, 1].set_title(f"Stego {SIZES[4]} B ({df.pct_kapasitas[4]:.1f}% kap.)\nPSNR {df.PSNR_dB[4]:.2f} dB, k={df.k_matrix[4]}")
ax[0, 2].imshow(np.clip(d4 * 255, 0, 255).astype(np.uint8)); ax[0, 2].set_title("|Selisih| ×255 (titik = nilai berubah)"); ax[0, 3].imshow(big[..., 1] & 1, cmap="gray"); ax[0, 3].set_title("Bidang LSB stego (G)")
ax[1, 0].imshow(cover[..., 1] & 1, cmap="gray"); ax[1, 0].set_title("Bidang LSB cover (G)"); ax[1, 1].imshow(full); ax[1, 1].set_title(f"Stego kapasitas penuh {SIZES[-1]} B\nPSNR {df.PSNR_dB.iloc[-1]:.2f} dB")
ax[1, 2].imshow(np.clip(d9 * 255, 0, 255).astype(np.uint8)); ax[1, 2].set_title("|Selisih| ×255 (kapasitas penuh)"); ax[1, 3].imshow(full[..., 1] & 1, cmap="gray"); ax[1, 3].set_title("Bidang LSB stego penuh (G)")
for a in ax.ravel(): a.axis("off")
fig.tight_layout(); save(fig, "fig3_visual")
# fig4 histogram
pl_full = make_payload(SIZES[-1]); s_rep, _ = sc.embed(cover, pl_full, PASSWORD, mode="replace"); s_mat, _ = sc.embed(cover, pl_full, PASSWORD, mode="match")
lo, hi = 90, 130; rg = np.arange(lo, hi)
fig, ax = plt.subplots(1, 3, figsize=(13, 3.4), sharey=True)
for a, im, t_, col in zip(ax, [cover, s_rep, s_mat], ["Cover asli", "LSB replace (kapasitas penuh)", "LSB matching (kapasitas penuh)"], [C1, C2, C3]):
    h = np.bincount(im.ravel(), minlength=256); a.bar(rg, h[lo:hi], color=col); a.set_title(t_); a.set_xlabel("Nilai piksel")
ax[0].set_ylabel("Frekuensi"); fig.suptitle("Histogram: LSB replace meratakan pasangan nilai (2k,2k+1) → 'staircase'; LSB matching tidak", fontsize=9)
fig.tight_layout(); save(fig, "fig4_histogram")
# fig5 entropi, korelasi, NIST
fig, ax = plt.subplots(1, 3, figsize=(14, 3.6))
ax[0].plot(x, df.H_plaintext, "o-", c=C2, label="Plaintext"); ax[0].plot(x, df.H_ciphertext, "s-", c=C1, label="Ciphertext (AES-GCM)"); ax[0].axhline(8, ls="--", c="gray", lw=.8)
ax[0].set_ylabel("Entropi Shannon (bit/byte)"); ax[0].set_title("Entropi sebelum vs sesudah enkripsi"); ax[0].legend(fontsize=7); logx(ax[0])
ax[1].plot(x, df.korelasi_cover, "o-", c=C1, label="Cover"); ax[1].plot(x, df.korelasi_stego, "x--", c=C2, label="Stego"); ax[1].set_ylabel("Korelasi horizontal")
ax[1].set_title("Korelasi piksel bertetangga"); ax[1].legend(fontsize=7); ax[1].set_ylim(df.korelasi_cover.iloc[0] - .01, df.korelasi_cover.iloc[0] + .003); logx(ax[1])
for col, lab, c in [("monobit_p", "Monobit", C1), ("runs_p", "Runs", C3), ("chi2_byte_p", "χ² byte", C4)]: ax[2].plot(x, df[col], "o-", c=c, label=lab)
ax[2].axhline(.01, ls="--", c=C2, lw=.9); ax[2].text(x.iloc[0], .012, "ambang p=0.01 (lolos jika di atas)", fontsize=7, color=C2); ax[2].set_ylabel("p-value"); ax[2].set_title("Uji keacakan ciphertext"); ax[2].legend(fontsize=7); logx(ax[2])
fig.tight_layout(); save(fig, "fig5_entropi_korelasi")
# fig6 steganalisis RS + chi2
fig, ax = plt.subplots(1, 3, figsize=(15, 4)); cols = [C2, C5, C4, C3]
for (name, g), col in zip(sdf.groupby("skema", sort=True), cols): ax[0].plot(g.rasio_true, g.RS_est, "o-", c=col, label=name)
ax[0].plot([0, 1], [0, 1], ":", c="gray", label="deteksi sempurna"); ax[0].axhline(base_rs, ls="--", c="k", lw=.7, label="cover bersih")
ax[0].set_xlabel("Rasio penyisipan sebenarnya (bit / nilai kanal)"); ax[0].set_ylabel("Estimasi RS"); ax[0].set_title("RS analysis (lebih dekat diagonal = lebih mudah terdeteksi)"); ax[0].legend(fontsize=6.5)
for (name, g), col in zip(sdf.groupby("skema", sort=True), cols): ax[1].plot(g.payload_B, g.chi2_p, "o-", c=col, label=name)
ax[1].axhline(.05, ls="--", c="gray", lw=.8); ax[1].set_xscale("log"); ax[1].set_xlabel("Payload (byte)"); ax[1].set_ylabel("p-value χ² (≈1 = terdeteksi)"); ax[1].set_title("Chi-kuadrat (Westfeld–Pfitzmann)")
for (name, g), col in zip(sdf.groupby("skema", sort=True), cols): ax[2].plot(g.payload_B, g.berubah_pct, "o-", c=col, label=name)
ax[2].set_xscale("log"); ax[2].set_yscale("log"); ax[2].set_xlabel("Payload (byte)"); ax[2].set_ylabel("% nilai kanal yang berubah"); ax[2].set_title("Jejak perubahan pada cover")
fig.tight_layout(); save(fig, "fig6_steganalisis")
# fig7 ML ROC / AUC
fig, ax = plt.subplots(1, 2, figsize=(12, 4))
a_roc = 0.25 if 0.25 in ml_alphas else ml_alphas[0]
for name, col in zip(SA.SCHEMES, cols):
    f, t_ = roc[(name, a_roc)]; ax[0].plot(f, t_, c=col, label=name)
ax[0].plot([0, 1], [0, 1], ":", c="gray"); ax[0].set_xlabel("False positive rate"); ax[0].set_ylabel("True positive rate"); ax[0].set_title(f"ROC detektor SPAM+ML (rasio {a_roc:.0%} kapasitas)"); ax[0].legend(fontsize=6.5)
for name, col in zip(SA.SCHEMES, cols):
    g = mldf[mldf.skema == name]; ax[1].errorbar(g.rasio_kapasitas, g.AUC, yerr=g.AUC_std, fmt="o-", c=col, capsize=2, label=name)
ax[1].axhline(.5, ls=":", c="gray"); ax[1].set_xlabel("Rasio penyisipan (fraksi kapasitas)"); ax[1].set_ylabel("AUC (0.5 = tak terdeteksi)"); ax[1].set_title("AUC leave-one-cover-out (rerata ± std antar citra)")
fig.tight_layout(); save(fig, "fig7_steganalisis_ml")
# fig8 robustness (heatmap)
piv = rdf.pivot(index="serangan", columns="profil", values="ekstraksi_berhasil").reindex([a for a, _ in A.SUITE])[list(profiles)]
fig, ax = plt.subplots(figsize=(8.4, 6)); ax.imshow(piv.values.astype(float), cmap="RdYlGn", vmin=-.2, vmax=1.2, aspect="auto"); ax.grid(False)
ax.set_xticks(range(len(piv.columns))); ax.set_xticklabels(piv.columns, fontsize=8); ax.set_yticks(range(len(piv.index))); ax.set_yticklabels(piv.index, fontsize=8)
for i in range(piv.shape[0]):
    for j in range(piv.shape[1]): ax.text(j, i, "✔ pulih" if piv.values[i, j] else "✘ gagal", ha="center", va="center", fontsize=8)
ax.set_title("Robustness: apakah payload (1 KB) pulih utuh setelah serangan?")
fig.tight_layout(); save(fig, "fig8_robustness")
# fig9 kapasitas
fig, ax = plt.subplots(1, 2, figsize=(13, 3.8)); wd = .2; xi = np.arange(len(cdf)); labs = [c.split(" ")[0] for c in cdf.cover]
for j, (col, lab, c) in enumerate([("kapasitas_B", "Default", C1), ("kapasitas_ECC1_B", "ECC 1", C3), ("kapasitas_ECC2_B", "ECC 2", C5), ("kapasitas_ECC3_B", "ECC 3", C2)]):
    ax[0].bar(xi + (j - 1.5) * wd, cdf[col] / 1024, wd, color=c, label=lab)
ax[0].set_xticks(xi); ax[0].set_xticklabels(labs, rotation=30); ax[0].set_ylabel("Kapasitas (KB)"); ax[0].set_title("Kapasitas maksimum per cover & level ECC"); ax[0].legend(fontsize=7)
ax[1].bar(xi - .2, cdf.kapasitas_B / 1024, .4, color=C1, label="Data acak / terkompresi"); ax[1].bar(xi + .2, cdf.teks_efektif_kompresi_B / 1024, .4, color=C3, label="Teks + kompresi zlib")
ax[1].set_xticks(xi); ax[1].set_xticklabels(labs, rotation=30); ax[1].set_ylabel("Payload efektif (KB)"); ax[1].set_title("Kompresi memperbesar kapasitas efektif"); ax[1].legend(fontsize=7)
fig.tight_layout(); save(fig, "fig9_kapasitas")
# fig10 multicover + efisiensi
fig, ax = plt.subplots(1, 3, figsize=(15, 3.8))
for (nm, g) in mdf.groupby("cover", sort=False): ax[0].plot(g.pct_kapasitas, g.PSNR_dB, "o-", ms=3, label=nm)
ax[0].set_xscale("log"); ax[0].set_xlabel("% kapasitas terpakai"); ax[0].set_ylabel("PSNR (dB)"); ax[0].set_title("PSNR pada 8 citra sampul"); ax[0].legend(fontsize=6)
for (nm, g) in mdf.groupby("cover", sort=False): ax[1].plot(g.pct_kapasitas, g.SSIM, "o-", ms=3, label=nm)
ax[1].set_xscale("log"); ax[1].set_xlabel("% kapasitas terpakai"); ax[1].set_ylabel("SSIM"); ax[1].set_title("SSIM pada 8 citra sampul")
ax[2].plot(df.pct_kapasitas, df.nilai_berubah_match_pct, "s--", c=C2, label="LSB matching biasa")
ax[2].plot(df.pct_kapasitas, df.nilai_berubah_pct, "o-", c=C1, label="Matrix embedding"); ax[2].set_xscale("log"); ax[2].set_yscale("log"); ax[2].set_xlabel("% kapasitas terpakai"); ax[2].set_ylabel("% nilai kanal berubah"); ax[2].set_title("Jumlah perubahan pada cover"); ax[2].legend(fontsize=7)
fig.tight_layout(); save(fig, "fig10_multicover")

# ---------------- ringkasan terminal
pd.set_option("display.width", 250, "display.max_columns", 40, "display.float_format", lambda v: f"{v:.4g}")
print("\n== PAYLOAD =="); print(df[["payload_B", "k_matrix", "pct_kapasitas", "PSNR_dB", "PSNR_match_dB", "gain_PSNR_dB", "SSIM", "BER", "hash_cocok", "H_ciphertext", "RS_est", "t_embed_ms", "t_extract_ms"]])
print("\n== ML STEGANALISIS =="); print(mldf.pivot(index="rasio_kapasitas", columns="skema", values="AUC"))
print("\n== ROBUSTNESS =="); print(piv)
print("\n== KAPASITAS =="); print(cdf[["cover", "kapasitas_B", "kapasitas_ECC3_B", "teks_efektif_kompresi_B"]])
print("\n== JENIS PAYLOAD =="); print(tdf); print("\n== BRUTE FORCE =="); print(brute)
