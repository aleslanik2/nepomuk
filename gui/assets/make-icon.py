"""Renders the nepomuk app icon (the vault door: an N behind a framed, hinged door) to icon-source.png.

The same drawing is kept as vector art in icon.svg (200 x 200 units); this script rasterises it
without any dependencies so the PNG can be regenerated anywhere.

Pure Python, no dependencies: `python3 make-icon.py`, then `cargo tauri icon icon-source.png`.
"""
import math
import struct
import zlib

N = 1024
# The door is drawn on a 200-unit grid; leave a margin so the rounded square sits inside the
# canvas like other desktop app icons.
SIZE = 880
OFFSET = (N - SIZE) / 2
UNIT = SIZE / 200

NAVY = (22, 35, 63)  # #16233F
TEAL = (95, 180, 170)  # #5FB4AA
WHITE = (255, 255, 255)


def smooth(d):
    """Coverage from a signed distance in pixels (negative inside), one pixel of anti-aliasing."""
    return max(0.0, min(1.0, 0.5 - d))


def round_box(x, y, left, top, width, height, radius):
    """Signed distance in grid units to a rounded rectangle."""
    hw, hh = width / 2, height / 2
    qx = abs(x - (left + hw)) - (hw - radius)
    qy = abs(y - (top + hh)) - (hh - radius)
    outside = math.hypot(max(qx, 0.0), max(qy, 0.0))
    return outside + min(max(qx, qy), 0.0) - radius


def poly(x, y, pts):
    d = float("inf")
    inside = False
    n = len(pts)
    for i in range(n):
        ax, ay = pts[i]
        bx, by = pts[(i + 1) % n]
        ex, ey = bx - ax, by - ay
        wx, wy = x - ax, y - ay
        t = max(0.0, min(1.0, (wx * ex + wy * ey) / (ex * ex + ey * ey)))
        d = min(d, math.hypot(wx - ex * t, wy - ey * t))
        if (ay > y) != (by > y) and x < ax + (y - ay) * ex / ey:
            inside = not inside
    return -d if inside else d


def scaled(pts, k=0.82):
    """The N sits on the door at 82 % of its full size, centred."""
    return [(100 + (px - 100) * k, 100 + (py - 100) * k) for px, py in pts]


def rect_pts(left, top, width, height):
    return [(left, top), (left + width, top), (left + width, top + height), (left, top + height)]


STEM_LEFT = scaled(rect_pts(52, 52, 24, 96))
STEM_RIGHT = scaled(rect_pts(124, 52, 24, 96))
DIAGONAL = scaled([(52, 52), (76, 52), (148, 148), (124, 148)])


def mix(a, b, t):
    return tuple(a[i] + (b[i] - a[i]) * t for i in range(3))


rows = []
for py in range(N):
    row = bytearray([0])
    y = (py + 0.5 - OFFSET) / UNIT
    for px in range(N):
        x = (px + 0.5 - OFFSET) / UNIT
        alpha = smooth(round_box(x, y, 0, 0, 200, 200, 46) * UNIT)
        if alpha <= 0:
            row += b"\x00\x00\x00\x00"
            continue
        col = NAVY
        # Door frame: a 4-unit outline of a rounded square inset by 24.
        col = mix(col, TEAL, smooth((abs(round_box(x, y, 24, 24, 152, 152, 28)) - 2) * UNIT))
        # Hinges on the left edge of the frame.
        hinge = min(round_box(x, y, 17, 58, 10, 24, 3), round_box(x, y, 17, 118, 10, 24, 3))
        col = mix(col, TEAL, smooth(hinge * UNIT))
        if 50 <= x <= 150 and 50 <= y <= 150:
            col = mix(col, WHITE, smooth(min(poly(x, y, STEM_LEFT), poly(x, y, STEM_RIGHT)) * UNIT))
            col = mix(col, TEAL, smooth(poly(x, y, DIAGONAL) * UNIT))
        row += bytes([round(col[0]), round(col[1]), round(col[2]), round(alpha * 255)])
    rows.append(bytes(row))


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", N, N, 8, 6, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")
with open("icon-source.png", "wb") as f:
    f.write(png)
print("icon-source.png written")
