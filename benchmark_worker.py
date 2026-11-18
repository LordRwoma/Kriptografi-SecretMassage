"""Isolated benchmark worker. Receives one scenario as JSON on stdin.

Timing and RSS sampling run in separate passes. No Streamlit imports, no
passwords in arguments or outputs, and no changes to the production algorithm.
"""
import gc
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import sys
import threading
import time

import numpy as np
import psutil

import image_stego as transport
import stegocrypt as sc
from image_io import encode_image, load_image

MIB = 2 ** 20


class RSSSampler:
    """Observed working set/RSS, including native allocations, at 2 ms intervals."""
    def __init__(self, interval=0.002):
        self.interval = interval
        self.process = psutil.Process()
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.active = None
        self.records = {}
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def _record(self, name, rss):
        record = self.records[name]
        record["rss_puncak_MiB"] = max(record["rss_puncak_MiB"], rss / MIB)
        record["sampel_rss"] += 1

    def sample(self):
        rss = self.process.memory_info().rss
        with self.lock:
            self._record("Total alur", rss)
            if self.active is not None:
                self._record(self.active, rss)

    def _loop(self):
        while not self.stop_event.wait(self.interval):
            self.sample()

    def _new_record(self):
        rss = self.process.memory_info().rss / MIB
        return dict(rss_awal_MiB=rss, rss_puncak_MiB=rss, sampel_rss=0)

    def __enter__(self):
        self.records["Total alur"] = self._new_record()
        self.thread.start()
        self.sample()
        return self

    def begin(self, name):
        with self.lock:
            self.records[name] = self._new_record()
            self.active = name
        self.sample()

    def end(self):
        self.sample()
        with self.lock:
            self.active = None

    def __exit__(self, *_):
        self.stop_event.set()
        self.thread.join()
        self.sample()
        for record in self.records.values():
            record["rss_kenaikan_MiB"] = max(0.0, record["rss_puncak_MiB"] - record["rss_awal_MiB"])


def pipeline(cover, payload, password, config, sampler=None):
    """Return only measurements and non-secret method labels; discard image outputs."""
    timings = {}

    def call(name, operation):
        if sampler:
            sampler.begin(name)
        start = time.perf_counter()
        try:
            return operation()
        finally:
            timings[name] = (time.perf_counter() - start) * 1000
            if sampler:
                sampler.end()

    start = time.perf_counter()
    if config["format"] == "PNG":
        stego, info = call("Penyisipan PNG", lambda: sc.embed(
            cover, payload, password, mode=config["mode"], ecc=config["ecc"], compress=config["compress"]))
        encoded = call("Encoding PNG", lambda: encode_image(stego))
        # Preserve grayscale just as the production transport does.
        saved = call("Pembacaan PNG", lambda: load_image(io.BytesIO(encoded)) if cover.ndim == 3
                     else transport._decode_gray(encoded))
        backend = "lsb"
    else:
        saved, info, encoded = call("Sisip-simpan-verifikasi JPEG", lambda: transport.embed(
            cover, payload, password, "JPEG", config["mode"], config["ecc"], config["compress"]))
        backend = "dct"

    def extract_verified():
        out = transport.extract(saved, password, backend=backend)
        if out != payload:
            raise ValueError("Payload hasil benchmark berbeda dari referensi.")

    call("Ekstraksi dan cek identik", extract_verified)
    timings["Total alur"] = (time.perf_counter() - start) * 1000
    method = "DCT-QIM + ECC 3" if backend == "dct" else f"{info['mode']}; k={info['k']}"
    return timings, dict(metode_aktual=method, k=info["k"], ecc_aktual=info["ecc"],
                         kompresi_aktual=info["compressed"], file_B=len(encoded))


def run_scenario(request):
    config = request["config"]
    cover = np.load(request["cover_path"], allow_pickle=False)
    payload = np.random.default_rng(config["seed"]).bytes(request["payload_B"])
    password = request["password"]
    # Each scenario uses a fresh child process. The warmup result is discarded.
    pipeline(cover, payload, password, config)
    rows = []
    for repeat in range(1, config["repeats"] + 1):
        gc.collect()
        timings, details = pipeline(cover, payload, password, config)
        gc.collect()
        with RSSSampler() as sampler:
            _, memory_details = pipeline(cover, payload, password, config, sampler)
        # Independent random salt/nonces may choose the same k but must never be reused.
        for phase, elapsed in timings.items():
            rows.append(dict(
                resolusi=f"{cover.shape[1]}x{cover.shape[0]}", piksel=int(np.prod(cover.shape[:2])),
                nilai_kanal=int(cover.size), payload_B=len(payload), format=config["format"],
                mode_diminta=config["mode"], ecc_diminta=config["ecc"], kompresi_diminta=config["compress"],
                seed=config["seed"], pengulangan=repeat, tahap=phase, waktu_ms=elapsed,
                **sampler.records[phase], **details,
                metode_memori=memory_details["metode_aktual"], payload_identik=True))
    versions = {name: importlib.metadata.version(name) for name in
                ("numpy", "pillow", "scipy", "cryptography", "reedsolo", "psutil")}
    return dict(rows=rows, metadata=dict(
        python=platform.python_version(), sistem=platform.platform(), cpu=platform.processor(),
        cpu_logis=os.cpu_count(), RAM_MiB=psutil.virtual_memory().total / MIB,
        pid=os.getpid(), versi=versions, cover_sha256=hashlib.sha256(cover.tobytes()).hexdigest(),
        payload_sha256=hashlib.sha256(payload).hexdigest(), pemanasan=1,
        interval_sampling_ms=2, timing_dan_memori="Dua lintasan terpisah; bukan satu operasi yang sama",
        catatan_memori="RSS/working set proses termasuk pustaka native. Puncak teramati, bukan puncak mutlak. "
                       "Baseline setelah pemanasan; allocator dapat mempertahankan memori antar pengulangan."))


if __name__ == "__main__":
    try:
        result = run_scenario(json.load(sys.stdin))
        print(json.dumps(result, allow_nan=False), flush=True)
    except Exception as exc:
        # A failed scenario is explicit and does not produce success measurements.
        print(json.dumps(dict(error=f"{type(exc).__name__}: {exc}")), flush=True)
        sys.exit(1)
