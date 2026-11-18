"""Benchmark orchestration and exports, independent of the Streamlit session."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

import cv2
import numpy as np
import pandas as pd

import image_stego as transport
import stegocrypt as sc


def payload_sizes(capacity, count=10):
    if count < 1 or capacity < count:
        raise ValueError(f"Kapasitas harus cukup untuk {count} ukuran payload berbeda.")
    # Fixed bytes across resolutions can be supplied instead for a controlled image-size study.
    return sorted(set(int(x) for x in np.linspace(1, capacity, count, dtype=np.int64)))


def validate_config(config):
    if config["format"] not in ("PNG", "JPEG") or config["mode"] not in sc.MODES:
        raise ValueError("Format atau mode benchmark tidak valid.")
    if config["ecc"] not in sc.ECC_NSYM or not 1 <= config["repeats"] <= 10:
        raise ValueError("ECC atau jumlah pengulangan tidak valid.")
    if not 0 <= config["seed"] < 2 ** 32:
        raise ValueError("Seed harus berada pada rentang 0 sampai 2^32-1.")


def resized_cover(cover, max_edge):
    if max_edge is None:
        return cover
    scale = max_edge / max(cover.shape[:2])
    h, w = max(8, round(cover.shape[0] * scale)), max(8, round(cover.shape[1] * scale))
    return cv2.resize(cover, (w, h), interpolation=cv2.INTER_AREA if scale < 1 else cv2.INTER_CUBIC)


def unique_edges(cover, edges):
    """Do not count 'Asli' and an identical requested size as two experiments."""
    seen, chosen = set(), []
    for edge in edges:
        if edge is None:
            shape = cover.shape[:2]
        else:
            scale = edge / max(cover.shape[:2])
            shape = (max(8, round(cover.shape[0] * scale)), max(8, round(cover.shape[1] * scale)))
        if shape not in seen:
            seen.add(shape)
            chosen.append(edge)
    return chosen


def run_benchmark(cover, password, config, edges=(None,), sizes=None, count=10, timeout=180):
    """Yield one completed scenario; each scenario gets a new isolated Python process.

    No password in the command line or files. Temporary covers are deleted on
    normal completion and exceptions. Existing stego/session results are untouched.
    """
    validate_config(config)
    if not password or not edges:
        raise ValueError("Password dan pilihan resolusi diperlukan.")
    scenarios = []
    for edge in unique_edges(cover, edges):
        image = resized_cover(cover, edge)
        capacity = transport.capacity_bytes(image.shape, config["format"], config["ecc"])
        chosen = payload_sizes(capacity, count) if sizes is None else sorted(set(sizes))
        if not chosen or any(not isinstance(n, int) or n < 1 or n > capacity for n in chosen):
            raise ValueError(f"Ukuran payload harus 1 sampai {capacity} byte pada resolusi {image.shape[:2]}.")
        scenarios.extend((image, n) for n in chosen)
    worker = Path(__file__).with_name("benchmark_worker.py")
    with tempfile.TemporaryDirectory(prefix="stegocrypt-benchmark-") as temp:
        path = Path(temp) / "cover.npy"
        previous = None
        for index, (image, size) in enumerate(scenarios):
            if image is not previous:
                np.save(path, image, allow_pickle=False)
                previous = image
            request = dict(cover_path=str(path), payload_B=size, password=password, config=config)
            try:
                completed = subprocess.run(
                    [sys.executable, str(worker)], input=json.dumps(request), encoding="utf-8",
                    capture_output=True, timeout=timeout, cwd=str(worker.parent),
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                result = json.loads(completed.stdout)
                if completed.returncode and "error" not in result:
                    result = dict(error="Proses benchmark berhenti sebelum selesai.")
            except subprocess.TimeoutExpired:
                result = dict(error=f"Batas waktu {timeout} detik untuk skenario ini terlampaui.")
            except json.JSONDecodeError:
                result = dict(error="Worker tidak dapat dimulai. Periksa instalasi requirements.txt pada Python aplikasi.")
            yield dict(index=index + 1, total=len(scenarios), payload_B=size,
                       resolusi=f"{image.shape[1]}x{image.shape[0]}", **result)


def summarize(rows):
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows).groupby(["format", "resolusi", "piksel", "payload_B", "tahap"], sort=False).agg(
        waktu_median_ms=("waktu_ms", "median"), waktu_min_ms=("waktu_ms", "min"),
        waktu_max_ms=("waktu_ms", "max"), waktu_std_ms=("waktu_ms", lambda x: x.std(ddof=0)),
        rss_awal_median_MiB=("rss_awal_MiB", "median"), rss_puncak_max_MiB=("rss_puncak_MiB", "max"),
        rss_kenaikan_median_MiB=("rss_kenaikan_MiB", "median"),
        pengulangan=("pengulangan", "count"), seluruh_payload_identik=("payload_identik", "all")).reset_index()


def export_zip(record):
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    buffer = io.BytesIO()
    summary = summarize(record["rows"])
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("benchmark_raw.csv", pd.DataFrame(record["rows"]).to_csv(index=False))
        archive.writestr("benchmark_summary.csv", summary.to_csv(index=False))
        archive.writestr("benchmark_metadata.json", json.dumps(
            {key: value for key, value in record.items() if key != "rows"}, ensure_ascii=False, indent=2))
        if not summary.empty:
            for index, (phase, group) in enumerate(summary.groupby("tahap", sort=False), start=1):
                figure = Figure(figsize=(9, 3.8), layout="constrained")
                FigureCanvasAgg(figure)
                axes = figure.subplots(1, 2)
                for resolution, part in group.groupby("resolusi"):
                    part = part.sort_values("payload_B")
                    axes[0].plot(part.payload_B, part.waktu_median_ms, marker="o", label=resolution)
                    axes[1].plot(part.payload_B, part.rss_puncak_max_MiB, marker="o", label=resolution)
                for axis, label in zip(axes, ("Waktu median (ms)", "Puncak RSS teramati (MiB)")):
                    axis.set(xlabel="Payload (byte)", ylabel=label)
                    axis.grid(alpha=0.25)
                    axis.legend(title="Resolusi")
                figure.suptitle(f"{record['config']['format']} - {phase}")
                png = io.BytesIO()
                figure.savefig(png, format="png", dpi=140)
                archive.writestr(f"grafik_{index}.png", png.getvalue())
    return buffer.getvalue()
