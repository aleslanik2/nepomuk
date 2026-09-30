"""Renders the nepomuk app icon (a wax seal with a halo of five stars) to icon-source.png.

Pure Python, no dependencies: `python3 make-icon.py`, then `cargo tauri icon icon-source.png`.
"""
import math
import struct
import zlib

N = 1024
C = N / 2

WAX = (158, 27, 50)
WAX_LIGHT = (190, 48, 70)
WAX_DARK = (112, 18, 36)
BRASS = (214, 178, 96)


def smooth(d):
    """Coverage from a signed distance (negative inside), one pixel of anti-aliasing."""
    return max(0.0, min(1.0, 0.5 - d))


def star_points(cx, cy, r_out, r_in, rot):
    pts = []
    for i in range(10):
        r = r_out if i % 2 == 0 else r_in
        a = rot + i * math.pi / 5
        pts.append((cx + r * math.sin(a), cy - r * math.cos(a)))
    return pts


def poly_sdf(x, y, pts):
    d = float("inf")
    inside = False
    n = len(pts)
    for i in range(n):
        ax, ay = pts[i]
        bx, by = pts[(i + 1) % n]
        ex, ey = bx - ax, by - ay
        wx, wy = x - ax, y - ay
        t = max(0.0, min(1.0, (wx * ex + wy * ey) / (ex * ex + ey * ey)))
        dx, dy = wx - ex * t, wy - ey * t
        d = min(d, math.hypot(dx, dy))
        if (ay > y) != (by > y) and x < ax + (y - ay) * ex / ey:
            inside = not inside
    return -d if inside else d


stars = []
for k in range(5):
    a = math.radians(-60 + k * 30)  # an arc above the keyhole
    cx = C + 262 * math.sin(a)
    cy = C - 40 - 262 * math.cos(a)
    pts = star_points(cx, cy, 44, 18, 0)
    stars.append((pts, cx - 50, cx + 50, cy - 50, cy + 50))


def keyhole_sdf(x, y):
    d_circle = math.hypot(x - C, y - (C + 40)) - 66
    # Trapezoid below the circle.
    top, bottom = C + 60, C + 250
    half_top, half_bottom = 30, 58
    if y < top:
        d_trap = top - y
    elif y > bottom:
        d_trap = y - bottom
    else:
        half = half_top + (half_bottom - half_top) * (y - top) / (bottom - top)
        d_trap = abs(x - C) - half
        d_trap = max(d_trap, top - y, y - bottom)
    return min(d_circle, d_trap)


def mix(a, b, t):
    return tuple(a[i] + (b[i] - a[i]) * t for i in range(3))


rows = []
for py in range(N):
    row = bytearray([0])
    y = py + 0.5
    for px in range(N):
        x = px + 0.5
        dx, dy = x - C, y - C
        r = math.hypot(dx, dy)
        th = math.atan2(dy, dx)
        edge = 452 + 12 * math.sin(9 * th) + 6 * math.sin(23 * th + 1.3) + 4 * math.sin(41 * th + 0.4)
        alpha = smooth(r - edge)
        if alpha <= 0:
            row += b"\x00\x00\x00\x00"
            continue
        # Light from the upper left.
        shade = max(0.0, min(1.0, 0.55 - (dx + dy) / (2.4 * N)))
        col = mix(WAX_DARK, WAX_LIGHT, shade)
        # Pressed ring.
        ring = smooth(abs(r - 352) - 10)
        col = mix(col, WAX_DARK, ring * 0.85)
        rim = smooth(abs(r - 366) - 2)
        col = mix(col, WAX_LIGHT, rim * 0.6)
        col = mix(col, WAX_DARK, smooth(keyhole_sdf(x, y)) * 0.95)
        for pts, x0, x1, y0, y1 in stars:
            if x0 <= x <= x1 and y0 <= y <= y1:
                col = mix(col, BRASS, smooth(poly_sdf(x, y, pts)))
        row += bytes([int(col[0]), int(col[1]), int(col[2]), int(alpha * 255)])
    rows.append(bytes(row))


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", N, N, 8, 6, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")
with open("icon-source.png", "wb") as f:
    f.write(png)
print("icon-source.png written")
