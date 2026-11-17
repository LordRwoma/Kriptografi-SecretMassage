"""Metrik kualitas, uji keacakan ciphertext, dan steganalisis (RS, chi-kuadrat, SPAM + klasifikasi ML)."""
import numpy as np
from scipy.special import erfc, gammaincc
from scipy.stats import chi2 as chi2_dist
from skimage.metrics import structural_similarity


# ---------------------------------------------------------------- kualitas citra
def mse(a, b):
    return float(np.mean((a.astype(np.float64) - b.astype(np.float64)) ** 2))


def psnr(a, b):
    m = mse(a, b)
    return float("inf") if m == 0 else float(10 * np.log10(255.0 ** 2 / m))


def ssim(a, b):
    return float(structural_similarity(a, b, channel_axis=2 if a.ndim == 3 else None, data_range=255))


def ber(bits_a, bits_b):
    return float(np.mean(np.asarray(bits_a) != np.asarray(bits_b)))


def adjacent_corr(img, direction="h"):
    x = img.astype(np.float64)
    if direction == "h":
        a, b = x[:, :-1].ravel(), x[:, 1:].ravel()
    elif direction == "v":
        a, b = x[:-1].ravel(), x[1:].ravel()
    else:
        a, b = x[:-1, :-1].ravel(), x[1:, 1:].ravel()
    return float(np.corrcoef(a, b)[0, 1])


# ---------------------------------------------------------------- keacakan ciphertext
def entropy_bytes(data: bytes):
    h = np.bincount(np.frombuffer(data, np.uint8), minlength=256).astype(np.float64)
    p = h[h > 0] / h.sum()
    return float(-(p * np.log2(p)).sum())


def nist_monobit(bits):
    n = bits.size
    s = abs(2 * int(bits.sum()) - n) / np.sqrt(n)
    return float(erfc(s / np.sqrt(2)))


def nist_runs(bits):
    n = bits.size
    pi = bits.mean()
    if abs(pi - 0.5) >= 2 / np.sqrt(n):
        return 0.0
    vobs = 1 + int(np.count_nonzero(bits[1:] != bits[:-1]))
    return float(erfc(abs(vobs - 2 * n * pi * (1 - pi)) / (2 * np.sqrt(2 * n) * pi * (1 - pi))))


def chi2_uniform_bytes(data: bytes):
    """p-value uji kebaikan-suai: byte ciphertext berdistribusi seragam (p>0.01 = lolos)."""
    h = np.bincount(np.frombuffer(data, np.uint8), minlength=256).astype(np.float64)
    e = h.sum() / 256
    return float(1 - chi2_dist.cdf(((h - e) ** 2 / e).sum(), 255))


def serial_corr(data: bytes):
    x = np.frombuffer(data, np.uint8).astype(np.float64)
    return float(np.corrcoef(x[:-1], x[1:])[0, 1]) if x.size > 2 else float("nan")


# ---------------------------------------------------------------- steganalisis: chi-kuadrat
def _chi2_p(values):
    h = np.bincount(np.asarray(values).ravel(), minlength=256).astype(np.float64)
    even, odd = h[0::2], h[1::2]
    exp = (even + odd) / 2
    m = exp > 5
    if m.sum() < 2:
        return 0.0
    stat = (((even - exp) ** 2)[m] / exp[m]).sum()
    return float(1 - chi2_dist.cdf(stat, m.sum() - 1))


def chi2_pvalue(img, windows=(0.05, 0.1, 0.25, 0.5, 1.0)):
    """Westfeld-Pfitzmann 'growing sample': nilai maksimum p di atas prefiks aliran piksel.
    p -> 1 = pasangan nilai (2k,2k+1) terekualisasi = indikasi LSB *replacement*."""
    v = np.ascontiguousarray(img).reshape(-1)
    return max(_chi2_p(v[:max(int(len(v) * w), 64)]) for w in windows)


# ---------------------------------------------------------------- steganalisis: RS analysis
def _disc(g):
    return np.abs(np.diff(g, axis=1)).sum(1)


def _apply(g, mask, kind):
    out = g.copy()
    m = mask.astype(bool)
    x = out[:, m]
    out[:, m] = (x ^ 1) if kind == 1 else (((x + 1) ^ 1) - 1)
    return out


def _rs_counts(g, mask):
    f0 = _disc(g)
    f1, fm = _disc(_apply(g, mask, 1)), _disc(_apply(g, mask, -1))
    return (f1 > f0).mean() - (f1 < f0).mean(), (fm > f0).mean() - (fm < f0).mean()


def rs_estimate(img):
    """RS analysis (Fridrich et al., 2001): estimasi rasio penyisipan (bit per nilai kanal)."""
    mask = np.array([0, 1, 1, 0])
    chans = [img] if img.ndim == 2 else [img[..., c] for c in range(img.shape[2])]
    ests = []
    for x in chans:
        x = x.astype(np.int32)
        w4 = (x.shape[1] // 4) * 4
        g = x[:, :w4].reshape(-1, 4)
        d0, d_0 = _rs_counts(g, mask)
        d1, d_1 = _rs_counts(g ^ 1, mask)
        a, b, c = 2 * (d1 + d0), (d_0 - d_1 - d1 - 3 * d0), (d0 - d_0)
        if abs(a) < 1e-12:
            ests.append(0.0); continue
        disc = b * b - 4 * a * c
        if disc < 0:
            ests.append(0.0); continue
        roots = [(-b + np.sqrt(disc)) / (2 * a), (-b - np.sqrt(disc)) / (2 * a)]
        z = min(roots, key=abs)
        ests.append(float(z / (z - 0.5)))
    return float(np.mean(ests))


# ---------------------------------------------------------------- steganalisis: SPAM + ML
def _trip_hist(d, m):
    a, b, c = d[..., :-2], d[..., 1:-1], d[..., 2:]
    return np.bincount((a * m * m + b * m + c).ravel(), minlength=m ** 3) / a.size


def spam_features(img, T=3):
    """Fitur SPAM orde-1 (Pevny et al., 2010): ko-okurensi 3 residu bertetangga, T=3 -> 2*343=686 dimensi."""
    m = 2 * T + 1
    chans = [img] if img.ndim == 2 else [img[..., c] for c in range(img.shape[2])]
    out = []
    for x in chans:
        x = x.astype(np.int16)
        clip = lambda d: (np.clip(d, -T, T) + T).astype(np.int64)
        h = _trip_hist(clip(x[:, :-1] - x[:, 1:]), m)
        v = _trip_hist(clip(x[:-1] - x[1:]).T, m)
        # diagonal & anti-diagonal (anti-diagonal = diagonal pada citra yang dicerminkan)
        def diag_hist(xx):
            D = clip(xx[:-1, :-1] - xx[1:, 1:])
            a, b, c = D[:-2, :-2], D[1:-1, 1:-1], D[2:, 2:]
            return np.bincount((a * m * m + b * m + c).ravel(), minlength=m ** 3) / a.size
        dd = diag_hist(x)
        da = diag_hist(x[:, ::-1])
        out.append(np.concatenate([(h + v) / 2, (dd + da) / 2]))
    return np.mean(out, axis=0)


def ml_detection_auc(feat_cover, feat_stego, groups):
    """AUC detektor (standardisasi + regresi logistik) dengan validasi *leave-one-cover-out*:
    latih pada patch dari citra lain, uji pada citra yang tidak pernah dilihat. Return (mean, std, P_E)."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score, roc_curve
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import make_pipeline
    X = np.vstack([feat_cover, feat_stego])
    y = np.r_[np.zeros(len(feat_cover)), np.ones(len(feat_stego))]
    g = np.r_[groups, groups]
    aucs, scores, ys = [], [], []
    for gi in np.unique(groups):
        tr, te = g != gi, g == gi
        clf = make_pipeline(StandardScaler(), LogisticRegression(C=0.05, max_iter=2000))
        clf.fit(X[tr], y[tr])
        s = clf.decision_function(X[te])
        aucs.append(roc_auc_score(y[te], s)); scores.append(s); ys.append(y[te])
    s, yy = np.concatenate(scores), np.concatenate(ys)
    fpr, tpr, _ = roc_curve(yy, s)
    pe = float(np.min(0.5 * (fpr + (1 - tpr))))
    return float(np.mean(aucs)), float(np.std(aucs)), pe, (fpr, tpr)
