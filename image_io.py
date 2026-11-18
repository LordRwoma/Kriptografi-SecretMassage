"""Image decoding shared by the GUI and CLI (never rotate stego pixels)."""
import io
import os
import re
import xml.etree.ElementTree as ET
import numpy as np
from PIL import Image, UnidentifiedImageError

IMAGE_TYPES = [
    "png", "jpg", "jpeg", "bmp", "webp", "tif", "tiff", "gif", "ico",
    "ppm", "pgm", "pbm", "pnm", "qoi", "jp2", "j2k", "jpx", "avif",
]
VECTOR_IMAGE_TYPES = ["svg"]
MAX_SVG_BYTES = 20 * 1024 * 1024


def _read_bytes(source):
    if isinstance(source, bytes):
        return source
    if hasattr(source, "getvalue"):
        return source.getvalue()
    if hasattr(source, "seek") and hasattr(source, "read"):
        source.seek(0)
        data = source.read()
        source.seek(0)
        return data
    with open(source, "rb") as stream:
        return stream.read()


def _is_svg(source):
    name = getattr(source, "name", source if isinstance(source, (str, os.PathLike)) else "")
    if str(name).lower().endswith(".svg"):
        return True
    if isinstance(source, (str, os.PathLike)):
        return False
    if isinstance(source, bytes):
        head = source[:4096]
    elif hasattr(source, "getvalue"):
        head = source.getvalue()[:4096]
    elif hasattr(source, "seek") and hasattr(source, "read"):
        source.seek(0)
        head = source.read(4096)
        source.seek(0)
    else:
        return False
    normalized = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    return b"<svg" in normalized


def _svg_dimensions(root, max_edge):
    view_box = root.attrib.get("viewBox")
    if view_box:
        values = [float(value) for value in re.split(r"[\s,]+", view_box.strip())]
        if len(values) != 4:
            raise ValueError("SVG memiliki viewBox yang tidak valid.")
        width, height = values[2:]
    else:
        lengths = []
        for key in ("width", "height"):
            match = re.fullmatch(r"\s*(\d+(?:\.\d*)?|\.\d+)(?:px)?\s*", root.attrib.get(key, ""))
            if not match:
                raise ValueError("SVG harus memiliki viewBox atau ukuran width/height dalam piksel.")
            lengths.append(float(match.group(1)))
        width, height = lengths
    if not np.isfinite(width) or not np.isfinite(height) or width <= 0 or height <= 0:
        raise ValueError("Ukuran SVG harus berupa angka positif yang valid.")
    scale = max_edge / max(width, height)
    out_width, out_height = max(1, round(width * scale)), max(1, round(height * scale))
    if out_width < 8 or out_height < 8:
        raise ValueError("Rasio SVG terlalu ekstrem untuk dipakai sebagai sampul.")
    return out_width, out_height


def _rasterize_svg(data, max_edge):
    if len(data) > MAX_SVG_BYTES:
        raise ValueError("Ukuran SVG terlalu besar (maksimal 20 MiB).")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("SVG harus menggunakan encoding UTF-8.") from exc
    if re.search(r"<!\s*(DOCTYPE|ENTITY)\b", text, flags=re.IGNORECASE):
        raise ValueError("SVG dengan deklarasi DTD/entity tidak didukung.")
    if re.search(r"(?:href\s*=\s*['\"]\s*(?:https?:|file:|//)|url\(\s*['\"]?\s*(?:https?:|file:|//))",
                 text, flags=re.IGNORECASE):
        raise ValueError("SVG dengan referensi gambar eksternal tidak didukung.")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("Berkas SVG tidak valid.") from exc
    if root.tag.rsplit("}", 1)[-1].lower() != "svg":
        raise ValueError("Berkas bukan dokumen SVG.")
    width, height = _svg_dimensions(root, max_edge)
    import resvg_py

    try:
        png = resvg_py.svg_to_bytes(
            svg_string=text, width=width, height=height, background="#ffffff"
        )
        with Image.open(io.BytesIO(png)) as image:
            image.load()
            return np.array(image.convert("RGB"))
    except (ValueError, TypeError, OSError) as exc:
        raise ValueError("SVG tidak dapat dirasterisasi. Periksa isi dan ukuran gambar.") from exc


def load_image(source, svg_max_edge=1024):
    """Decode the first frame to RGB. EXIF orientation is intentionally not applied."""
    if _is_svg(source):
        return _rasterize_svg(_read_bytes(source), svg_max_edge)
    try:
        if hasattr(source, "seek"):
            source.seek(0)
        with Image.open(source) as im:
            im.load()
            return np.array(im.convert("RGB"))
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as exc:
        raise ValueError("Berkas tidak dapat dibaca sebagai gambar yang didukung.") from exc


def encode_image(image, format="PNG"):
    format = format.upper()
    if format == "JPG":
        format = "JPEG"
    if format not in ("PNG", "JPEG"):
        raise ValueError("Format keluaran harus PNG atau JPEG.")
    stream = io.BytesIO()
    options = dict(quality=95, subsampling=0) if format == "JPEG" else {}
    Image.fromarray(image).save(stream, format=format, **options)
    return stream.getvalue()
