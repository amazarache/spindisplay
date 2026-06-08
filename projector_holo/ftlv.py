"""FTLV (FTL LED Video) file format — header parser, builder, and a
GIF/PNG → FTLV transcoder skeleton.

We learned this format from a SpinDisplay app pcap (2026-06-04). The
on-device file format begins with the ASCII tag ``FTLV`` and was sent to
the fan inside a cmd 0x36 frame via TCP 50110. We captured the 48-byte
header but **not** the actual frame payload, so the per-frame pixel
layout is INFERRED — it must be confirmed by either (a) sniffing a
larger upload session that includes frame bytes, or (b) reading a real
``.ftlv`` file off the fan's SD card.

48-byte header layout, all integers little-endian uint32 unless noted::

    offset  size  field          captured value     interpretation
    ------  ----  -------------  -----------------  -----------------------
        0    4    magic          b"FTLV"            ASCII signature
        4    4    version        1                  format version
        8    4    size_a         40248              total file size on device?
       12    4    block_size     512                512-byte storage block
       16    4    size_c         39720              size_a - 528 ≈ data section
       20    4    reserved_0     0
       24    4    frame_count    16                 number of frames in the loop
       28    4    reserved_1     0
       32    4    reserved_2     0
       36    4    big_const      10000000           10M — bitrate? duration µs?
       40    4    flag           1                  uncompressed? endless loop?
       44    4    fps_or_other   10                 plausibly the frame rate

Unknowns we still need to characterise:
- Per-frame pixel encoding (RGB triplets? palette + index? per-blade
  packed bytes?). The radial geometry — F56 has 56 cm diameter; the
  blade-LED count is reported as **224** on most spec sheets in the
  F30/F56/F65/F80/F100 family, with **480 angular slices** per rotation,
  but this is uncorroborated for this specific firmware.
- Whether ``size_c`` is the data section or includes a footer / sector
  alignment padding.
- The meaning of ``big_const = 10_000_000``. Could be a duration in
  microseconds (10s), a bitrate (10 Mbps), or a sample clock.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Iterable

MAGIC = b"FTLV"
HEADER_FORMAT = "<4sIIIIIIIIIII"  # 4s + 11 uint32 = 48 bytes
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
assert HEADER_SIZE == 48

# Default geometry assumptions for the F56 — provisional, not yet confirmed
# against a real frame payload. Change DEFAULT_BLADE_LEDS / DEFAULT_SLICES
# when we get a known-good ``.ftlv`` file to compare against.
DEFAULT_BLADE_LEDS = 224       # LEDs per blade, F56 specification sheets
DEFAULT_SLICES = 480           # angular positions per rotation
DEFAULT_FPS = 10               # matches the pcap's `fps_or_other` field


@dataclass
class FTLVHeader:
    """Decoded FTLV file header (48 bytes)."""

    version: int = 1
    size_a: int = 0           # total on-device file size — fill at pack time
    block_size: int = 512
    size_c: int = 0           # data-section size — fill at pack time
    reserved_0: int = 0
    frame_count: int = 0
    reserved_1: int = 0
    reserved_2: int = 0
    big_const: int = 10_000_000
    flag: int = 1
    fps_or_other: int = DEFAULT_FPS

    def pack(self) -> bytes:
        return struct.pack(
            HEADER_FORMAT,
            MAGIC,
            self.version,
            self.size_a,
            self.block_size,
            self.size_c,
            self.reserved_0,
            self.frame_count,
            self.reserved_1,
            self.reserved_2,
            self.big_const,
            self.flag,
            self.fps_or_other,
        )

    @classmethod
    def unpack(cls, buf: bytes) -> "FTLVHeader":
        if len(buf) < HEADER_SIZE:
            raise ValueError(f"buf too small: {len(buf)} < {HEADER_SIZE}")
        fields = struct.unpack(HEADER_FORMAT, buf[:HEADER_SIZE])
        if fields[0] != MAGIC:
            raise ValueError(f"bad magic: {fields[0]!r} (expected {MAGIC!r})")
        return cls(
            version=fields[1],
            size_a=fields[2],
            block_size=fields[3],
            size_c=fields[4],
            reserved_0=fields[5],
            frame_count=fields[6],
            reserved_1=fields[7],
            reserved_2=fields[8],
            big_const=fields[9],
            flag=fields[10],
            fps_or_other=fields[11],
        )

    def describe(self) -> str:
        return (
            f"FTLV v{self.version}\n"
            f"  total bytes (size_a)  : {self.size_a}\n"
            f"  block_size            : {self.block_size}\n"
            f"  data bytes (size_c)   : {self.size_c}\n"
            f"  frame_count           : {self.frame_count}\n"
            f"  big_const             : {self.big_const}\n"
            f"  flag                  : {self.flag}\n"
            f"  fps_or_other          : {self.fps_or_other}\n"
        )


# ---------------------------------------------------------------------------
# Radial slice transform: rectangular image → fan-native frame
# ---------------------------------------------------------------------------


def radial_sample(
    img: "PIL.Image.Image",  # noqa: F821 -- imported lazily below
    *,
    blade_leds: int = DEFAULT_BLADE_LEDS,
    slices: int = DEFAULT_SLICES,
) -> list[list[tuple[int, int, int]]]:
    """Convert a square RGB image into a polar-coordinate sample grid.

    Returns a ``slices``-tall x ``blade_leds``-wide array of (R,G,B)
    tuples. Each row is one angular position (0 = right, increasing
    counter-clockwise to match math convention); each column is one LED
    out from the center. Conversion is nearest-neighbour for now —
    bilinear can be added once we know whether the device firmware
    expects gamma-corrected values.

    The image must already be in RGB mode; non-square images are
    cropped to a centered square before sampling.
    """
    from PIL import Image

    if img.mode != "RGB":
        img = img.convert("RGB")

    w, h = img.size
    side = min(w, h)
    if w != h:
        left = (w - side) // 2
        top = (h - side) // 2
        img = img.crop((left, top, left + side, top + side))

    px = img.load()
    cx = cy = (side - 1) / 2.0
    r_max = side / 2.0

    grid: list[list[tuple[int, int, int]]] = []
    two_pi_over_slices = 2.0 * math.pi / slices
    for a in range(slices):
        theta = a * two_pi_over_slices
        cos_t = math.cos(theta)
        sin_t = math.sin(theta)
        row: list[tuple[int, int, int]] = []
        for r in range(blade_leds):
            rad = (r + 0.5) / blade_leds * r_max  # +0.5 to sample mid-LED
            x = int(round(cx + rad * cos_t))
            y = int(round(cy - rad * sin_t))  # negate Y so theta=π/2 points up
            x = max(0, min(side - 1, x))
            y = max(0, min(side - 1, y))
            row.append(px[x, y])
        grid.append(row)
    return grid


def encode_frame_rgb24(grid: list[list[tuple[int, int, int]]]) -> bytes:
    """Naive packing: flatten the polar grid in row-major (angle, then
    radius) and emit 3-byte RGB triples.

    This is a guess. The actual on-device format may use:
    - 16-bit (5-6-5) RGB to halve the bytes
    - GRB ordering for WS2812-class LEDs
    - Per-blade packed format with delta encoding
    - Palette + index

    Replace this function when we have a confirmed frame layout from
    a real ``.ftlv`` file off the SD card.
    """
    buf = bytearray()
    for row in grid:
        for (r, g, b) in row:
            buf.append(r)
            buf.append(g)
            buf.append(b)
    return bytes(buf)


# ---------------------------------------------------------------------------
# End-to-end transcoder
# ---------------------------------------------------------------------------


def transcode_image_sequence(
    frames: Iterable["PIL.Image.Image"],  # noqa: F821
    *,
    blade_leds: int = DEFAULT_BLADE_LEDS,
    slices: int = DEFAULT_SLICES,
    fps: int = DEFAULT_FPS,
) -> bytes:
    """Build a full FTLV file from an iterable of PIL Images.

    Returns the bytes that would be sent to the fan as the body of a
    cmd 0x36 ``upload`` chunk (or chunks, once chunking is mapped).
    """
    frame_bytes_list: list[bytes] = []
    for img in frames:
        grid = radial_sample(img, blade_leds=blade_leds, slices=slices)
        frame_bytes_list.append(encode_frame_rgb24(grid))

    data = b"".join(frame_bytes_list)
    header = FTLVHeader(
        size_a=HEADER_SIZE + len(data),
        size_c=len(data),
        frame_count=len(frame_bytes_list),
        fps_or_other=fps,
    )
    return header.pack() + data


def transcode_gif(path: str | Path, **kwargs) -> bytes:
    """Convenience wrapper: open a GIF/PNG/APNG and transcode all frames.

    Per the project's OWASP standard, the image format is loaded with
    Pillow (no shell interpolation) and we explicitly handle multi-frame
    inputs via ``ImageSequence``.
    """
    from PIL import Image, ImageSequence

    path = Path(path)
    with Image.open(path) as src:
        frames = [f.copy() for f in ImageSequence.Iterator(src)]
    return transcode_image_sequence(frames, **kwargs)


# ---------------------------------------------------------------------------
# Captured-pcap fixture for regression tests
# ---------------------------------------------------------------------------

PCAP_HEADER_FIXTURE = bytes.fromhex(
    "46 54 4c 56 01 00 00 00 38 9d 00 00 00 02 00 00 "
    "28 9b 00 00 00 00 00 00 10 00 00 00 00 00 00 00 "
    "00 00 00 00 80 96 98 00 01 00 00 00 0a 00 00 00".replace(" ", "")
)
assert len(PCAP_HEADER_FIXTURE) == HEADER_SIZE


def _self_test() -> None:
    h = FTLVHeader.unpack(PCAP_HEADER_FIXTURE)
    assert h.version == 1, h
    assert h.size_a == 40248, h
    assert h.block_size == 512, h
    assert h.size_c == 39720, h
    assert h.frame_count == 16, h
    assert h.big_const == 10_000_000, h
    assert h.flag == 1, h
    assert h.fps_or_other == 10, h
    # round-trip
    repack = h.pack()
    assert repack == PCAP_HEADER_FIXTURE, (repack.hex(), PCAP_HEADER_FIXTURE.hex())
    print("ftlv self-test OK — pcap header round-trips")
    print(h.describe())


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        _self_test()
    elif sys.argv[1] == "inspect" and len(sys.argv) == 3:
        data = Path(sys.argv[2]).read_bytes()
        h = FTLVHeader.unpack(data)
        print(h.describe())
        print(f"file size: {len(data)} bytes")
        print(f"data after header: {len(data) - HEADER_SIZE} bytes")
        if h.size_c and h.frame_count:
            print(f"bytes/frame (size_c / frame_count): {h.size_c / h.frame_count:.1f}")
    elif sys.argv[1] == "encode" and len(sys.argv) == 4:
        src, dst = sys.argv[2], sys.argv[3]
        out = transcode_gif(src)
        Path(dst).write_bytes(out)
        print(f"wrote {len(out)} bytes to {dst}")
    else:
        print(
            "usage:\n"
            "  python -m projector_holo.ftlv                       # self-test\n"
            "  python -m projector_holo.ftlv inspect <file.ftlv>   # dump header\n"
            "  python -m projector_holo.ftlv encode <in.gif> <out.ftlv>  # transcode"
        )
