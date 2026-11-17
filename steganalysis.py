"""Eksperimen steganalisis: bandingkan 4 skema penyisipan dengan RS, chi-kuadrat, dan detektor SPAM+ML.
Pembanding menyisipkan bit acak (setara ciphertext) langsung pada primitif -> tanpa biaya KDF, ribuan sampel cepat."""
import os
import numpy as np
from skimage import data
import stegocrypt as sc
import metrics as M

SCHEMES = {
    "A. LSB replace sekuensial (naif)": dict(mode="replace", scatter=False),
    "B. LSB replace acak berkunci": dict(mode="replace", scatter=True),
    "C. LSB matching acak berkunci": dict(mode="match", scatter=True),
    "D. Matching + matrix embedding (diusulkan)": dict(mode="matrix", scatter=True),
}


def embed_random(cover, alpha, mode, scatter, rng):
    """Sisipkan alpha*(kapasitas bit) bit acak dengan primitif StegoCrypt-X. Return stego uint8."""
    flat = cover.reshape(-1).copy()
    h = sc.HEADER_BITS
    avail = flat.size - h
    nbits = max(8, int(alpha * avail))
    bits = rng.integers(0, 2, nbits).astype(np.uint8)
    k = sc._choose_k(nbits, avail, sc.MAX_K if mode == "matrix" else 1)
    need = -(-nbits // k) * (2 ** k - 1) if k > 1 else nbits
    key = rng.bytes(32)
    sel = sc._body_positions(key, avail, need, h, scatter)
    out = flat.copy()
    out[sel] = sc._set_lsb(flat[sel], bits, mode != "replace") if k == 1 else sc._matrix_embed(flat[sel], bits, k)[0]
    return out.reshape(cover.shape), k


def rgb_covers():
    return {"astronaut": data.astronaut(), "coffee": data.coffee(), "chelsea": data.chelsea(),
            "rocket": data.rocket(), "immunohistochemistry": data.immunohistochemistry(),
            "hubble_deep_field": data.hubble_deep_field(), "retina": data.retina()}


def make_patches(covers, size=128, stride=64, per_cover=40, seed=0):
    rng = np.random.default_rng(seed)
    P, G = [], []
    for gi, (name, im) in enumerate(covers.items()):
        pos = [(y, x) for y in range(0, im.shape[0] - size + 1, stride) for x in range(0, im.shape[1] - size + 1, stride)]
        rng.shuffle(pos)
        for y, x in pos[:per_cover]:
            P.append(np.ascontiguousarray(im[y:y + size, x:x + size])); G.append(gi)
    return P, np.array(G)


def run_ml(alphas=(0.05, 0.1, 0.25, 0.5, 1.0), seed=0, verbose=True):
    P, G = make_patches(rgb_covers(), seed=seed)
    f_cov = np.array([M.spam_features(p) for p in P])
    rows, roc = [], {}
    for name, kw in SCHEMES.items():
        for a in alphas:
            rng = np.random.default_rng(1000 + int(a * 100))
            S = [embed_random(p, a, rng=rng, **kw)[0] for p in P]
            f_st = np.array([M.spam_features(s) for s in S])
            auc, sd, pe, curve = M.ml_detection_auc(f_cov, f_st, G)
            rows.append(dict(skema=name, rasio_kapasitas=a, AUC=auc, AUC_std=sd, P_E=pe, n_patch=len(P)))
            roc[(name, a)] = curve
            if verbose:
                print(f"  ML  {name[:34]:<34} alpha={a:<5} AUC={auc:.3f}±{sd:.3f}  P_E={pe:.3f}", flush=True)
    return rows, roc
