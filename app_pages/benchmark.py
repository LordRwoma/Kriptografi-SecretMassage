"""User-driven time/memory benchmarks; never overwrites the last stego result."""
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

import benchmark_service as bench
import image_stego as transport
from image_io import IMAGE_TYPES, VECTOR_IMAGE_TYPES
from ui_common import S, SAMPLES, MODE_LABEL, ECC_LABEL, read_upload, image_key


def render():
    st.title("Complexity & Efisiensi")
    st.caption("Ukur waktu dan memori dengan payload uji sintetis. Hasil penyisipan terakhir tetap tersimpan.")
    source = st.radio("Cover untuk benchmark", ["Contoh bawaan", "Cover penyisipan terakhir", "Unggah cover"],
                      horizontal=True, key="benchmark_source")
    cover = None
    if source == "Contoh bawaan":
        sample = st.selectbox("Contoh cover benchmark", list(SAMPLES), key="benchmark_sample")
        cover = SAMPLES[sample]()
    elif source == "Cover penyisipan terakhir":
        if S.get("result") is not None:
            cover = S["result"]["cover"]
        else:
            st.info("Buat hasil di halaman Sisipkan dahulu atau gunakan contoh bawaan.")
    else:
        cover = read_upload(st.file_uploader("Cover benchmark", type=IMAGE_TYPES + VECTOR_IMAGE_TYPES,
                                            key="benchmark_cover"))

    output_format = st.selectbox("Format benchmark", ["PNG", "JPEG"], key="benchmark_format")
    if output_format == "PNG":
        mode = st.selectbox("Metode benchmark", list(MODE_LABEL), format_func=MODE_LABEL.get)
        ecc = st.selectbox("ECC benchmark", list(ECC_LABEL), format_func=ECC_LABEL.get)
        if mode == "matrix" and ecc:
            st.caption("ECC aktif memakai k=1: LSB matching tanpa pengelompokan matrix.")
    else:
        mode, ecc = "match", 3
        st.info("JPEG memakai DCT-QIM + ECC 3. Waktu sisip, simpan, dan verifikasi internal "
                "diukur sebagai satu tahap karena jalur ini dapat mengulang proses penyimpanan.")
    compress = st.checkbox("Kompresi payload benchmark", value=False)
    st.caption("Payload berupa byte pseudoacak dengan seed tercatat. Kompresi nonaktif secara default "
               "agar ukuran uji tidak menyusut. Salt dan nonce enkripsi tetap acak.")
    edges_labels = st.multiselect("Resolusi cover (sisi terpanjang)", ["Asli", "512", "1024", "2048"], default=["Asli"])
    edges = [None if label == "Asli" else int(label) for label in edges_labels]
    if cover is not None:
        normalized = bench.unique_edges(cover, edges)
        if len(normalized) < len(edges):
            st.caption("Pilihan resolusi yang menghasilkan dimensi sama dihitung sekali.")
        edges = normalized
    repeats = st.number_input("Pengulangan terukur", min_value=1, max_value=10, value=5, step=1)
    seed = st.number_input("Seed payload", min_value=0, max_value=2**32 - 1, value=2026, step=1)
    sizing = st.radio("Ukuran payload benchmark", ["10 ukuran, byte sama di semua resolusi",
                     "10 ukuran, mengikuti kapasitas tiap resolusi", "Ukuran manual (byte)"], key="benchmark_sizing")
    manual = st.text_input("Daftar ukuran byte, pisahkan dengan koma", "16, 64, 256, 512", disabled=sizing != "Ukuran manual (byte)")
    password = st.text_input("Password benchmark", type="password", key="benchmark_password")
    config = dict(format=output_format, mode=mode, ecc=ecc, compress=compress, repeats=int(repeats), seed=int(seed))
    sizes, valid, capacities = None, cover is not None and bool(edges), []
    if valid:
        capacities = [transport.capacity_bytes(bench.resized_cover(cover, edge).shape, output_format, ecc) for edge in edges]
        try:
            if sizing == "Ukuran manual (byte)":
                sizes = sorted(set(int(value.strip()) for value in manual.split(",")))
                if not sizes or sizes[0] < 1 or sizes[-1] > min(capacities):
                    raise ValueError(f"Ukuran harus antara 1 dan {min(capacities):,} byte.")
            elif sizing == "10 ukuran, byte sama di semua resolusi":
                sizes = bench.payload_sizes(min(capacities))
            elif min(capacities) < 10:
                raise ValueError("Kapasitas tidak cukup untuk 10 ukuran berbeda.")
        except ValueError as exc:
            st.warning(str(exc))
            valid = False
    if valid:
        scenario_count = len(edges) * (len(sizes) if sizes is not None else 10)
        st.caption(f"{scenario_count} skenario × {int(repeats)} pengulangan. Tiap skenario memiliki satu pemanasan; "
                   "pengukuran waktu dan memori dijalankan pada lintasan terpisah. "
                   "Encoding/pembacaan diukur di memori, tanpa I/O disk atau unggahan browser.")
        st.write("Ukuran payload (byte):", sizes if sizes is not None else "10 ukuran dari 1 byte sampai kapasitas masing-masing resolusi")

    if st.button("Jalankan benchmark", type="primary", disabled=not valid or not password):
        record = dict(rows=[], scenarios=[], errors=[], config=config, resolusi=edges_labels,
                      ukuran_byte=sizes, sumber_cover=source, cover_sha256=image_key(cover),
                      waktu_UTC=datetime.now(timezone.utc).isoformat())
        progress = st.progress(0.0)
        status = st.empty()
        with st.spinner("Mengukur di proses terpisah; hasil muncul setelah setiap skenario..."):
            try:
                for result in bench.run_benchmark(cover, password, config, edges, sizes):
                    status.caption(f"Skenario {result['index']}/{result['total']}: "
                                   f"{result['resolusi']}, {result['payload_B']:,} byte")
                    progress.progress(result["index"] / result["total"])
                    if "error" in result:
                        record["errors"].append({key: result[key] for key in ("resolusi", "payload_B", "error")})
                    else:
                        record["rows"].extend(result["rows"])
                        record["scenarios"].append(dict(resolusi=result["resolusi"], payload_B=result["payload_B"],
                                                         metadata=result["metadata"]))
            except (ValueError, OSError) as exc:
                record["errors"].append(dict(error=str(exc)))
        S["benchmark_result"] = record
        S.pop("benchmark_zip", None)

    record = S.get("benchmark_result")
    if record:
        st.subheader("Hasil benchmark terakhir")
        local_time = datetime.fromisoformat(record["waktu_UTC"]).astimezone(timezone(timedelta(hours=7)))
        st.caption(f"Dijalankan {local_time:%d-%m-%Y %H:%M} WIB · {record['config']['format']} · "
                   f"{record['config']['repeats']} pengulangan. Mengubah pilihan di atas memerlukan pengujian ulang.")
        if record["errors"]:
            st.warning("Sebagian atau seluruh skenario gagal. Skenario gagal tidak dimasukkan sebagai hasil pengukuran.")
            st.dataframe(pd.DataFrame(record["errors"]), hide_index=True)
        summary = bench.summarize(record["rows"])
        if not summary.empty:
            st.dataframe(summary, hide_index=True)
            total = summary[summary.tahap == "Total alur"]
            st.metric("Skenario terverifikasi", len(total))
            phase = st.selectbox("Tahap pada grafik", list(summary.tahap.unique()),
                                 index=list(summary.tahap.unique()).index("Total alur"))
            chosen = summary[summary.tahap == phase]
            st.write("Waktu median terhadap ukuran payload (ms)")
            st.line_chart(chosen.pivot(index="payload_B", columns="resolusi", values="waktu_median_ms"))
            st.write("Puncak RSS teramati terhadap ukuran payload (MiB)")
            st.line_chart(chosen.pivot(index="payload_B", columns="resolusi", values="rss_puncak_max_MiB"))
            st.download_button("Unduh ringkasan (CSV)", summary.to_csv(index=False).encode("utf-8-sig"),
                               "benchmark_summary.csv", "text/csv")
            if "benchmark_zip" not in S:
                S["benchmark_zip"] = bench.export_zip(record)
            st.download_button("Unduh hasil lengkap dan grafik (ZIP)", S["benchmark_zip"],
                               "benchmark.zip", "application/zip")
            with st.expander("Data mentah dan lingkungan pengujian"):
                st.dataframe(pd.DataFrame(record["rows"]), hide_index=True)
                st.json(record["scenarios"][0]["metadata"])

    st.caption("Memori diukur sebagai RSS/working set proses, termasuk alokasi pustaka native. "
               "Sampling 2 ms menghasilkan puncak teramati; lonjakan singkat bisa terlewat. "
               "Baseline diambil setelah pemanasan; allocator dapat mempertahankan memori. "
               "Kenaikan RSS yang kecil tidak berarti algoritma tidak memakai memori.")
    with st.expander("Penjelasan complexity / kompleksitas algoritma"):
        st.markdown("""
Gunakan **N** = jumlah nilai kanal carrier, **B** = ukuran blob setelah enkripsi/ECC,
dan **m** = jumlah posisi body yang dipakai (m ≤ N). Pada JPEG, carrier berisi
empat koefisien per blok 8×8; transformasi blok tetap menambah kerja linear terhadap piksel.

| Bagian kode | Pertumbuhan waktu | Memori tambahan |
|---|---|---|
| scrypt + HKDF | Parameter scrypt tetap; juga bergantung panjang password | Memori scrypt sesuai N_scrypt, r, p; tetap untuk konfigurasi ini |
| AES-GCM | O(B) dengan overhead tetap | O(B) |
| Urutan posisi `_keyed_order` | PRF O(N); pengurutan subset O(m log m); batas konservatif keseluruhan O(N log N) | O(N + m) |
| LSB / matrix dengan k dibatasi 12 | O(m + B) | O(m + B) |
| Reed–Solomon dengan blok dan level tetap | O(B) terhadap banyaknya blok | O(B) |
| DCT / IDCT blok 8×8 | O(jumlah piksel) | O(jumlah piksel) |

Untuk jalur berkunci, batas konservatif inti penyisipan/ekstraksi adalah
**O(N log N + B)** waktu dan **O(N + B + memori scrypt)** ruang. `argpartition`
menyeleksi subset sebelum diurutkan; pada muatan penuh cabang kode memakai
`argsort` seluruh carrier. Ukuran matrix dan jumlah percobaan JPEG dibatasi konstanta.
Kompresi opsional serta codec gambar memiliki biaya tambahan dan diukur dalam benchmark.

Grafik adalah **hasil empiris pada perangkat pengujian**, bukan pembuktian Big-O.
Untuk mengamati pengaruh resolusi saja, gunakan jumlah byte payload yang sama
di semua resolusi. PNG dan JPEG memiliki tahap berbeda dan perlu dibahas terpisah.
Pada JPEG, waktu ekstraksi di tabel adalah percobaan tambahan setelah verifikasi internal.
""")


render()
