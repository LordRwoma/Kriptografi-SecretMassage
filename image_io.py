"""Image decoding shared by the GUI and CLI (never rotate stego pixels)."""
import io
import numpy as np
from PIL import Image, UnidentifiedImageError

IMAGE_TYPES = ["png", "jpg", "jpeg", "bmp", "webp", "tif", "tiff"]


def load_image(source):
    """Decode the first frame to RGB. EXIF orientation is intentionally not applied."""
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
