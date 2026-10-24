#!/usr/bin/env python3
"""Convert images into sleep-screen BMPs for CrossPoint.

Output is uncompressed 24-bit BMP at the panel's portrait resolution, the
format USER_GUIDE.md recommends for the "Custom" sleep screen. Transparency
is flattened onto white, EXIF rotation is applied, and images are either
center-cropped to fill the screen (default) or scaled to fit with white
borders (--fit).

Copy the output folder to the SD card root as `.sleep/` (or `sleep/`) for a
random image per sleep, or a single file as `/sleep.bmp`.

Usage:
  python scripts/img2sleep.py IMAGE_OR_DIR [...] [-o OUT_DIR] [--fit] [--size WxH]

Examples:
  python scripts/img2sleep.py ~/Pictures/xteink -o ~/Pictures/xteink/sleep
  python scripts/img2sleep.py photo.jpg --fit
  python scripts/img2sleep.py art/ --size 528x792   # X3
"""

import argparse
import sys
from pathlib import Path

from PIL import Image, ImageOps, UnidentifiedImageError

DEFAULT_SIZE = (480, 800)  # X4 / X4 Pro portrait; X3 is 528x792
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff"}


def parse_size(value):
    try:
        width, height = (int(part) for part in value.lower().split("x"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected WIDTHxHEIGHT, got {value!r}")
    if width <= 0 or height <= 0:
        raise argparse.ArgumentTypeError("width and height must be positive")
    return width, height


def collect_inputs(paths):
    files = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(p for p in path.iterdir() if p.suffix.lower() in IMAGE_SUFFIXES))
        elif path.is_file():
            files.append(path)
        else:
            print(f"skip: {path} not found", file=sys.stderr)
    return files


def to_sleep_image(src, size, fit):
    img = ImageOps.exif_transpose(Image.open(src))
    if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
        rgba = img.convert("RGBA")
        img = Image.new("RGB", rgba.size, "white")
        img.paste(rgba, mask=rgba.getchannel("A"))
    else:
        img = img.convert("RGB")
    if fit:
        return ImageOps.pad(img, size, method=Image.Resampling.LANCZOS, color="white")
    return ImageOps.fit(img, size, method=Image.Resampling.LANCZOS)


def main():
    parser = argparse.ArgumentParser(description="Convert images into CrossPoint sleep-screen BMPs.")
    parser.add_argument("inputs", nargs="+", type=Path, help="image files and/or directories of images")
    parser.add_argument("-o", "--output", type=Path, default=Path("sleep"), help="output directory (default: ./sleep)")
    parser.add_argument("--fit", action="store_true", help="scale to fit with white borders instead of cropping")
    parser.add_argument("--size", type=parse_size, default=DEFAULT_SIZE, help="WIDTHxHEIGHT (default: 480x800)")
    args = parser.parse_args()

    sources = collect_inputs(args.inputs)
    if not sources:
        print("No images found.", file=sys.stderr)
        return 1

    args.output.mkdir(parents=True, exist_ok=True)
    failed = 0
    for src in sources:
        dest = args.output / f"{src.stem}.bmp"
        try:
            to_sleep_image(src, args.size, args.fit).save(dest, "BMP")
        except (UnidentifiedImageError, OSError) as err:
            print(f"fail: {src.name}: {err}", file=sys.stderr)
            failed += 1
            continue
        print(f"ok:   {src.name} -> {dest}")

    print(f"{len(sources) - failed}/{len(sources)} converted into {args.output}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
