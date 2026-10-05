#!/usr/bin/env python3
"""Draws the 1024x1024 Keepsake icon (a keyhole on a blue rounded square) as a PNG. No dependencies."""
import struct
import zlib
from pathlib import Path

SIZE = 1024
MARGIN, RADIUS = 100, 185  # macOS icon grid
TOP, BOTTOM = (0x5B, 0x8C, 0xFF), (0x2F, 0x5F, 0xE0)
KEYHOLE = (0xF5, 0xF7, 0xFB)


def in_rounded_square(x: int, y: int) -> bool:
    lo, hi = MARGIN, SIZE - MARGIN
    if not (lo <= x < hi and lo <= y < hi):
        return False
    cx = min(max(x, lo + RADIUS), hi - RADIUS)
    cy = min(max(y, lo + RADIUS), hi - RADIUS)
    return (x - cx) ** 2 + (y - cy) ** 2 <= RADIUS**2


def in_keyhole(x: int, y: int) -> bool:
    if (x - 512) ** 2 + (y - 430) ** 2 <= 120**2:
        return True
    if 470 <= y <= 720:
        half = 55 + (y - 470) * (95 - 55) / (720 - 470)
        return abs(x - 512) <= half
    return False


def pixel(x: int, y: int) -> tuple:
    if not in_rounded_square(x, y):
        return (0, 0, 0, 0)
    if in_keyhole(x, y):
        return (*KEYHOLE, 255)
    t = (y - MARGIN) / (SIZE - 2 * MARGIN)
    return tuple(round(a + (b - a) * t) for a, b in zip(TOP, BOTTOM)) + (255,)


def png(width: int, height: int, rows: list) -> bytes:
    raw = b"".join(b"\x00" + bytes(row) for row in rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


rows = [bytearray(b for x in range(SIZE) for b in pixel(x, y)) for y in range(SIZE)]
out = Path(__file__).with_name("icon.png")
out.write_bytes(png(SIZE, SIZE, rows))
print(f"wrote {out}")
