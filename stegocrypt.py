"""
StegoCrypt-X v2  --  Kriptografi (AES-256-GCM) + Steganografi (LSB Matching + Matrix Embedding)
=============================================================================================
PENGIRIM : password --scrypt--> master --HKDF--> {kunci AES-256 | kunci PRF posisi | mask header}
           payload --(zlib opsional)--> AES-256-GCM --(Reed-Solomon opsional)--> blob
           blob --LSB matching / matrix embedding @ posisi acak berkunci--> stego-image
PENERIMA : stego-image -> baca header -> turunkan kunci -> baca bit di posisi acak
           -> (RS decode) -> AES-GCM decrypt + verifikasi tag -> (zlib) -> payload asli

Tata letak bit (tanpa magic number; seluruh aliran tampak acak):
    HEADER 256 bit @ 256 nilai-kanal pertama  : salt(16B) | nonce(12B) | ctrl(4B) XOR mask
        ctrl = [ k:4 | ecc:2 | zlib:1 | rsv:1 | panjang blob:24 ]
        mode tahan-banting (ecc>0): header diulang 5x (1280 bit) + voting mayoritas
    BODY   @ permutasi acak berkunci (AES-256-CTR sebagai PRF -> argsort; stabil lintas versi NumPy)

Matrix embedding (kode Hamming, k bit per grup 2^k-1 nilai, maks 1 perubahan/grup) menurunkan jumlah
piksel yang berubah hingga ~5x untuk payload kecil => PSNR naik & lebih sulit dideteksi steganalisis.
"""
import os
import zlib
import numpy as np
import reedsolo
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LEN, NONCE_LEN, CTRL_LEN, TAG_LEN = 16, 12, 4, 16
HEADER_BYTES = SALT_LEN + NONCE_LEN + CTRL_LEN            # 32 byte
HEADER_BITS = HEADER_BYTES * 8                            # 256 bit
HEADER_REPEAT = 5
ROBUST_HEADER_BITS = HEADER_BITS * HEADER_REPEAT          # 1280 bit
ECC_NSYM = {0: 0, 1: 32, 2: 64, 3: 128}                   # simbol paritas RS per blok 255 B
MAX_K = 12                                                # kode Hamming maks (2^12-1 = 4095 nilai/grup)
MAX_BLOB = 2 ** 24 - 1                                    # batas field panjang 24 bit
MAX_DECOMPRESSED = 64 * 2 ** 20
SCRYPT_N = 2 ** 15                                        # 32 MiB, ~90 ms/tebakan
INFO = b"stegocrypt-x/v2"
MODES = ("matrix", "match", "replace")


class ExtractionError(Exception):
    """Password salah, tidak ada data, kerusakan melebihi kemampuan ECC, atau stego dimodifikasi."""


# ------------------------------------------------------------------ kripto
def _derive(password: str, salt: bytes):
    master = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=8, p=1).derive(password.encode())
    okm = HKDFExpand(hashes.SHA256(), 32 + 32 + CTRL_LEN, INFO).derive(master)
    return okm[:32], okm[32:64], okm[64:68]               # kunci AES, kunci PRF posisi, mask ctrl


def kdf_time_probe(password="x"):
    """Satu tebakan password (scrypt + HKDF) -- dasar estimasi brute force."""
    _derive(password, b"\x00" * SALT_LEN)


def _keyed_order(key: bytes, n: int, m: int) -> np.ndarray:
    """m indeks pertama dari permutasi acak [0,n) yang ditentukan PRF AES-256-CTR (deterministik)."""
    if m <= 0:
        return np.empty(0, np.int64)
    ks = Cipher(algorithms.AES(key), modes.CTR(b"\x00" * 16)).encryptor().update(b"\x00" * (8 * n))
    r = np.frombuffer(ks, dtype="<u8")
    if m >= n:
        return np.argsort(r, kind="stable").astype(np.int64)
    part = np.argpartition(r, m - 1)[:m]
    return part[np.argsort(r[part], kind="stable")].astype(np.int64)


def _rand_signs(n: int) -> np.ndarray:
    b = np.unpackbits(np.frombuffer(os.urandom((n + 7) // 8), np.uint8))[:n]
    return b.astype(np.int16) * 2 - 1


# ------------------------------------------------------------------ ECC & kapasitas
def _rs_len(L: int, nsym: int) -> int:
    return L if nsym == 0 else L + -(-L // (255 - nsym)) * nsym


def _rs_payload_max(B: int, nsym: int) -> int:
    if nsym == 0:
        return B
    full, rem = divmod(B, 255)
    return full * (255 - nsym) + max(0, rem - nsym)


def header_bits(ecc: int) -> int:
    return ROBUST_HEADER_BITS if ecc else HEADER_BITS


def capacity_bytes(shape, ecc: int = 0) -> int:
    """Payload plaintext maksimum (byte, tanpa kompresi) untuk cover `shape`."""
    total = int(np.prod(shape))
    blob_max = min((total - header_bits(ecc)) // 8, MAX_BLOB)
    return max(0, _rs_payload_max(blob_max, ECC_NSYM[ecc]) - TAG_LEN)


def _choose_k(n_bits: int, avail: int, kmax: int) -> int:
    for k in range(min(kmax, MAX_K), 1, -1):
        if -(-n_bits // k) * (2 ** k - 1) <= avail:
            return k
    return 1


# ------------------------------------------------------------------ steganografi (primitif bit)
def _set_lsb(vals: np.ndarray, bits: np.ndarray, match: bool) -> np.ndarray:
    vals = vals.astype(np.uint8)
    if not match:
        return (vals & 0xFE) | bits.astype(np.uint8)
    need = (vals & 1) != bits
    step = _rand_signs(vals.size)
    step = np.where(vals == 0, 1, np.where(vals == 255, -1, step))
    return np.where(need, vals.astype(np.int16) + step, vals).astype(np.uint8)


def _matrix_embed(v: np.ndarray, bits: np.ndarray, k: int):
    """Hamming(2^k-1, 2^k-1-k) matrix embedding. v: len = G*(2^k-1). Mengembalikan (nilai baru, #perubahan)."""
    n = 2 ** k - 1
    G = v.size // n
    msg = np.zeros(G * k, np.int64)
    msg[:bits.size] = bits
    mval = (msg.reshape(G, k) << np.arange(k - 1, -1, -1)).sum(1)
    g = v.reshape(G, n).copy()
    idx = np.arange(1, n + 1, dtype=np.int64)
    syn = np.bitwise_xor.reduce(np.where((g & 1) == 1, idx, 0), axis=1)
    diff = syn ^ mval
    rows = np.flatnonzero(diff)
    cols = diff[rows] - 1
    x = g[rows, cols].astype(np.int16)
    step = _rand_signs(rows.size)
    step = np.where(x == 0, 1, np.where(x == 255, -1, step))
    g[rows, cols] = (x + step).astype(np.uint8)
    return g.reshape(-1), int(rows.size)


def _matrix_read(v: np.ndarray, k: int, n_bits: int) -> np.ndarray:
    n = 2 ** k - 1
    g = v.reshape(-1, n)
    idx = np.arange(1, n + 1, dtype=np.int64)
    syn = np.bitwise_xor.reduce(np.where((g & 1) == 1, idx, 0), axis=1)
    bits = (syn[:, None] >> np.arange(k - 1, -1, -1)) & 1
    return bits.reshape(-1)[:n_bits].astype(np.uint8)


def _body_positions(pkey: bytes, avail: int, need: int, h: int, scatter: bool) -> np.ndarray:
    if not scatter:                                         # baseline naif (hanya untuk ablasi)
        return np.arange(h, h + need, dtype=np.int64)
    return _keyed_order(pkey, avail, need) + h


def _read_body(flat: np.ndarray, sel: np.ndarray, k: int, n_bits: int) -> np.ndarray:
    v = flat[sel]
    return (v & 1).astype(np.uint8)[:n_bits] if k == 1 else _matrix_read(v, k, n_bits)


# ------------------------------------------------------------------ API utama
def embed(cover: np.ndarray, data: bytes, password: str, mode: str = "matrix", scatter: bool = True,
          ecc: int = 0, compress: bool = False):
    """Enkripsi `data` lalu sisipkan ke `cover` (uint8, 2D/3D).
    mode: 'matrix' (default: LSB matching + matrix embedding) | 'match' (LSB matching ±1) | 'replace'.
    ecc : 0..3 -> level Reed-Solomon (0 = tanpa ECC). ecc>0 memaksa k=1 (matrix embedding memperbesar error).
    """
    if mode not in MODES:
        raise ValueError(f"mode harus salah satu dari {MODES}")
    if ecc not in ECC_NSYM:
        raise ValueError("ecc harus 0,1,2,3")
    cover = np.ascontiguousarray(cover, dtype=np.uint8)
    flat = cover.reshape(-1).copy()
    payload, comp = data, 0
    if compress:
        z = zlib.compress(data, 9)
        if len(z) < len(data):
            payload, comp = z, 1
    nsym = ECC_NSYM[ecc]
    h = header_bits(ecc)
    avail = flat.size - h
    enc_len = _rs_len(len(payload) + TAG_LEN, nsym)
    if avail < 8 or enc_len > min(avail // 8, MAX_BLOB):
        raise ValueError(f"Payload {len(data)} B (efektif {len(payload)} B) melebihi kapasitas "
                         f"{capacity_bytes(cover.shape, ecc)} B")
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    ekey, pkey, mask = _derive(password, salt)
    k = _choose_k(enc_len * 8, avail, MAX_K if (mode == "matrix" and not ecc) else 1)
    ctrl = ((k << 4 | ecc << 2 | comp << 1) << 24) | enc_len
    masked = (ctrl ^ int.from_bytes(mask, "big")).to_bytes(CTRL_LEN, "big")
    header = salt + nonce + masked
    ct = AESGCM(ekey).encrypt(nonce, payload, header)                 # ciphertext || tag, AAD = header
    blob = bytes(reedsolo.RSCodec(nsym).encode(ct)) if nsym else ct
    assert len(blob) == enc_len
    body_bits = np.unpackbits(np.frombuffer(blob, np.uint8))
    hbits = np.unpackbits(np.frombuffer(header, np.uint8))
    if ecc:
        hbits = np.tile(hbits, HEADER_REPEAT)
    need = -(-body_bits.size // k) * (2 ** k - 1) if k > 1 else body_bits.size
    sel = _body_positions(pkey, avail, need, h, scatter)

    new = flat.copy()
    match = mode != "replace"
    new[:h] = _set_lsb(flat[:h], hbits, match)
    if k == 1:
        new[sel] = _set_lsb(flat[sel], body_bits, match)
    else:
        new[sel], _ = _matrix_embed(flat[sel], body_bits, k)
    changed = int(np.count_nonzero(new != flat))
    info = dict(salt=salt, nonce=nonce, header=header, sel=sel, k=k, ecc=ecc, compressed=bool(comp), mode=mode,
                header_bits=h, payload_len=len(data), plain_len=len(payload), blob_len=len(blob),
                n_body_bits=int(body_bits.size), body_bits=body_bits, n_bits=int(body_bits.size + hbits.size),
                changed=changed, ciphertext=ct, blob=blob,
                efficiency=(body_bits.size + hbits.size) / max(changed, 1))
    return new.reshape(cover.shape), info


def _try_extract(flat, password, scatter, vote):
    hb = ROBUST_HEADER_BITS if vote else HEADER_BITS
    if flat.size <= hb + 8:
        raise ExtractionError("Citra terlalu kecil")
    raw = flat[:hb] & 1
    hbits = ((raw.reshape(HEADER_REPEAT, HEADER_BITS).sum(0) * 2) > HEADER_REPEAT).astype(np.uint8) if vote else raw
    header = np.packbits(hbits).tobytes()
    salt, nonce, masked = header[:SALT_LEN], header[SALT_LEN:SALT_LEN + NONCE_LEN], header[SALT_LEN + NONCE_LEN:]
    ekey, pkey, mask = _derive(password, salt)
    ctrl = int.from_bytes(masked, "big") ^ int.from_bytes(mask, "big")
    flags, L = ctrl >> 24, ctrl & 0xFFFFFF
    k, ecc, comp, rsv = flags >> 4, (flags >> 2) & 3, (flags >> 1) & 1, flags & 1
    h = header_bits(ecc)
    if not (1 <= k <= MAX_K) or rsv or (vote and not ecc) or L < TAG_LEN or L * 8 > flat.size - h:
        raise ExtractionError("Header tidak valid (password salah / tidak ada pesan)")
    nb = L * 8
    need = -(-nb // k) * (2 ** k - 1) if k > 1 else nb
    if need > flat.size - h:
        raise ExtractionError("Header tidak valid (password salah / tidak ada pesan)")
    sel = _body_positions(pkey, flat.size - h, need, h, scatter)
    blob = np.packbits(_read_body(flat, sel, k, nb)).tobytes()
    if ecc:
        try:
            blob = bytes(reedsolo.RSCodec(ECC_NSYM[ecc]).decode(blob)[0])
        except reedsolo.ReedSolomonError:
            raise ExtractionError("ECC gagal: kerusakan melebihi kemampuan koreksi Reed-Solomon")
    try:
        plain = AESGCM(ekey).decrypt(nonce, blob, header)
    except InvalidTag:
        raise ExtractionError("Autentikasi GCM gagal (password salah / stego dimodifikasi)")
    if comp:
        d = zlib.decompressobj()
        out = d.decompress(plain, MAX_DECOMPRESSED)
        if d.unconsumed_tail:
            raise ExtractionError("Hasil dekompresi terlalu besar")
        return out
    return plain


def extract(stego: np.ndarray, password: str, scatter: bool = True) -> bytes:
    flat = np.ascontiguousarray(stego, dtype=np.uint8).reshape(-1)
    try:
        return _try_extract(flat, password, scatter, vote=False)
    except ExtractionError as first:
        if flat.size > ROBUST_HEADER_BITS + 8:               # header mungkin rusak -> coba voting 5 salinan
            try:
                return _try_extract(flat, password, scatter, vote=True)
            except ExtractionError:
                pass
        raise first


def read_body_bits(stego: np.ndarray, info: dict) -> np.ndarray:
    """Bit body (sebelum RS decode) yang terbaca dari `stego` pada posisi asli -- untuk menghitung BER."""
    flat = np.ascontiguousarray(stego, dtype=np.uint8).reshape(-1)
    return _read_body(flat, info["sel"], info["k"], info["n_body_bits"])
