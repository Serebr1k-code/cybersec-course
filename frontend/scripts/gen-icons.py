#!/usr/bin/env python3
"""Generate the CTF Learning Tree PWA icons.

Draws the app's radial-tree glyph (a root node, two children and four leaves)
in the app accent colour on the dark app background, then downsamples with
LANCZOS for crisp anti-aliased edges.  Outputs:

  public/icons/icon-192.png           192x192  (manifest "any")
  public/icons/icon-512.png           512x512  (manifest "any")
  public/icons/icon-512-maskable.png  512x512  (manifest "maskable", padded)
  public/icons/apple-touch-icon.png   180x180  (iOS home screen)

Run:  python3 frontend/scripts/gen-icons.py
"""
from pathlib import Path

from PIL import Image, ImageDraw

BG = (7, 11, 17, 255)        # --bg  #070b11
NODE = (56, 189, 248, 255)   # --accent #38bdf8
NODE_2 = (34, 197, 94, 255)  # --green  #22c55e
EDGE = (30, 58, 95, 255)     # dim blue for the connecting lines

OUT = Path(__file__).resolve().parent.parent / "public" / "icons"

# Glyph geometry in a 512x512 reference space.
ROOT = (256, 392, 34)
CHILDREN = [(150, 286, 27), (362, 286, 27)]
LEAVES = [(92, 182, 21), (208, 182, 21), (304, 182, 21), (420, 182, 21)]
EDGES = [
    (ROOT, CHILDREN[0]), (ROOT, CHILDREN[1]),
    (CHILDREN[0], LEAVES[0]), (CHILDREN[0], LEAVES[1]),
    (CHILDREN[1], LEAVES[2]), (CHILDREN[1], LEAVES[3]),
]

SS = 4  # supersampling factor


def draw_glyph(img: Image.Image, scale: float, dx: float, dy: float) -> None:
    d = ImageDraw.Draw(img)
    for (ax, ay, _), (bx, by, _) in EDGES:
        d.line(
            [dx + ax * scale, dy + ay * scale, dx + bx * scale, dy + by * scale],
            fill=EDGE,
            width=max(2, int(10 * scale)),
        )
    for x, y, r in [ROOT, *CHILDREN]:
        d.ellipse(
            [dx + (x - r) * scale, dy + (y - r) * scale,
             dx + (x + r) * scale, dy + (y + r) * scale],
            fill=NODE,
        )
    for x, y, r in LEAVES:
        d.ellipse(
            [dx + (x - r) * scale, dy + (y - r) * scale,
             dx + (x + r) * scale, dy + (y + r) * scale],
            fill=NODE_2,
        )


def render(size: int, maskable: bool = False) -> Image.Image:
    big = size * SS
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    radius = 0 if maskable else int(big * 0.22)
    d.rounded_rectangle([0, 0, big - 1, big - 1], radius=radius, fill=BG)
    # Maskable icons must keep art inside the ~80% safe zone.
    scale = (big / 512.0) * (0.72 if maskable else 0.92)
    offset = (big - 512 * scale) / 2.0
    draw_glyph(img, scale, offset, offset)
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    render(192).save(OUT / "icon-192.png")
    render(512).save(OUT / "icon-512.png")
    render(512, maskable=True).save(OUT / "icon-512-maskable.png")
    render(180).save(OUT / "apple-touch-icon.png")
    for p in sorted(OUT.glob("*.png")):
        print(f"{p.relative_to(OUT.parent.parent)}  {p.stat().st_size} bytes")


if __name__ == "__main__":
    main()
