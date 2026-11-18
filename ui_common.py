"""Shared Streamlit helpers and labels for StegoCrypt-X pages."""
import hashlib
import os
import re

import numpy as np
import streamlit as st
from skimage import data as skdata

import image_stego as transport
from image_io import IMAGE_TYPES, VECTOR_IMAGE_TYPES, load_image

S = st.session_state
HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = {
    "astronaut (512 × 512)": skdata.astronaut,
    "coffee (400 × 600)": skdata.coffee,
    "chelsea (300 × 451)": skdata.chelsea,
    "rocket (427 × 640)": skdata.rocket,
    "immunohistochemistry (512 × 512)": skdata.immunohistochemistry,
}
MODE_LABEL = {
    "matrix": "Matrix embedding + LSB matching",
    "match": "LSB matching ±1",
    "replace": "LSB replacement",
}
ECC_LABEL = {
    0: "Tanpa ECC",
    1: "ECC 1 — RS(255,223)",
    2: "ECC 2 — RS(255,191)",
    3: "ECC 3 — RS(255,127)",
}
IMAGE_FORMAT_HELP = "Raster: PNG, JPG/JPEG, BMP, WebP, TIF/TIFF, GIF, ICO, PPM/PGM, JPEG 2000, AVIF. Sampul juga menerima SVG."
METRIC_HELP = {
    "PSNR (dB)": "Perkiraan kualitas terhadap cover asli. Nilai lebih tinggi berarti perbedaan lebih kecil.",
    "SSIM": "Kemiripan struktur visual, biasanya 0–1. Nilai mendekati 1 berarti lebih mirip.",
    "MSE": "Rata-rata kuadrat selisih piksel terhadap cover. Nilai lebih rendah berarti lebih mirip.",
    "Waktu + verifikasi": "Waktu untuk menyisipkan, menyimpan, membaca ulang, dan memastikan pesan bisa diekstrak.",
    "BER": "Proporsi bit pesan yang berubah sebelum koreksi ECC. Nilai 0 berarti tidak ada bit yang berubah.",
}
SOURCE_LABELS = {
    "extract": "Sumber gambar untuk ekstraksi",
    "analysis": "Sumber gambar untuk steganalisis",
    "attack": "Sumber gambar untuk uji serangan",
    "evaluation": "Sumber gambar untuk evaluasi",
}


def read_upload(upload, svg_max_edge=1024):
    if upload is None:
        return None
    try:
        image = load_image(upload, svg_max_edge=svg_max_edge)
        if min(image.shape[:2]) < 8:
            raise ValueError("Gunakan gambar minimal 8 × 8 piksel.")
        return image
    except ValueError as exc:
        st.error(str(exc))
        return None


def image_key(image):
    return hashlib.sha256(str(image.shape).encode() + image.tobytes()).hexdigest()


def show_metrics(values):
    for col, (label, val) in zip(st.columns(len(values)), values.items()):
        col.metric(label, "—" if val is None else val, help=METRIC_HELP.get(label))


def fmt(value, digits=4):
    if value is None:
        return "—"
    return "∞" if np.isinf(value) else f"{value:.{digits}f}"


def safe_filename(name, extension):
    name = os.path.basename(name.replace("\\", "/")).strip()
    stem, suffix = os.path.splitext(name)
    if suffix.lower() in {".png", ".jpg", ".jpeg"}:
        name = stem
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")
    return f"{name or 'stego'}.{extension.lstrip('.')}"


def safe_payload_filename(name):
    name = os.path.basename(name.replace("\\", "/")).strip()
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")
    return name or "hasil_ekstraksi.bin"


def target_selector(key, with_cover=False):
    source = st.radio(
        SOURCE_LABELS[key],
        ["Hasil penyisipan terakhir", "Unggah gambar"],
        horizontal=True,
        key=f"{key}_source",
    )
    if source == "Hasil penyisipan terakhir":
        result = S.get("result")
        if result is None:
            st.info("Belum ada hasil penyisipan. Buat pesan di halaman Sisipkan atau pilih unggah gambar.")
            return None
        filename = result.get(
            "filename",
            "stego.jpg" if result.get("format") == "JPEG" else "stego.png",
        )
        st.caption(
            f"Hasil tersimpan: {result['format']} · {filename} · "
            f"{len(result['payload']):,} byte payload"
        )
        return dict(stego=result["stego"], cover=result["cover"],
                    expected=result["payload"], info=result["info"])

    upload = st.file_uploader(
        "Gambar stego (raster)", type=IMAGE_TYPES, key=f"{key}_stego",
        help="Unggah file PNG/JPEG stego asli. Hindari mengedit atau mengompres ulang.",
    )
    image = read_upload(upload)
    cover = None
    if with_cover:
        cover_upload = st.file_uploader(
            "Cover asli untuk perbandingan kualitas (opsional)",
            type=IMAGE_TYPES + VECTOR_IMAGE_TYPES,
            key=f"{key}_cover",
            help=IMAGE_FORMAT_HELP,
        )
        svg_max_edge = 1024
        if cover_upload and cover_upload.name.lower().endswith(".svg"):
            svg_max_edge = st.selectbox(
                "Resolusi maksimum rasterisasi SVG",
                [512, 1024, 2048],
                index=1,
                key=f"{key}_svg_width",
                help="SVG dirender ke raster sebelum dihitung metriknya.",
            )
        cover = read_upload(cover_upload, svg_max_edge=svg_max_edge)
        if cover is not None and image is not None and cover.shape != image.shape:
            st.error("Dimensi cover dan stego berbeda. Unggah pasangan dengan dimensi yang sama.")
            return None
    return None if image is None else dict(stego=image, cover=cover, expected=None, info=None)
