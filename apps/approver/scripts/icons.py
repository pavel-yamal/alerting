"""App icon and launch image for iOS (and Android later): `python3 scripts/icons.py`.

Apple refuses the stock Capacitor icon, and an icon with transparency. This draws a
red warning triangle with an exclamation mark on a dark navy square, supersampled
for smooth edges. Needs Pillow (`pip install pillow`). Writes into the generated
ios/ project; run after `npx cap add ios`.
"""

from __future__ import annotations

import pathlib

from PIL import Image, ImageDraw

APP = pathlib.Path(__file__).resolve().parent.parent
NAVY = (15, 29, 51)
RED = (217, 45, 32)
WHITE = (255, 255, 255)


def mark(size: int, scale: float) -> Image.Image:
    """The sign alone, on navy, `scale` of the square's side wide."""
    s = size * 4
    image = Image.new("RGB", (s, s), NAVY)
    draw = ImageDraw.Draw(image)
    w = s * scale
    cx, top = s / 2, (s - w * 0.88) / 2
    tri = [(cx, top), (cx + w / 2, top + w * 0.88), (cx - w / 2, top + w * 0.88)]
    # Rounded corners: the triangle shrunk towards its centre, then grown back by
    # a radius (edges stroked, a disc at each vertex) -- a stroked outline alone
    # leaves a notch where it closes.
    r = w * 0.05
    gx, gy = sum(x for x, _ in tri) / 3, sum(y for _, y in tri) / 3
    inner = []
    for x, y in tri:
        d = ((x - gx) ** 2 + (y - gy) ** 2) ** 0.5
        k = (d - 2 * r) / d
        inner.append((gx + (x - gx) * k, gy + (y - gy) * k))
    draw.polygon(inner, fill=RED)
    for a, b in zip(inner, inner[1:] + inner[:1]):
        draw.line([a, b], fill=RED, width=int(2 * r))
    for x, y in inner:
        draw.ellipse([x - r, y - r, x + r, y + r], fill=RED)
    bar_w = w * 0.11
    draw.rounded_rectangle(
        [cx - bar_w / 2, top + w * 0.30, cx + bar_w / 2, top + w * 0.62],
        radius=bar_w / 2, fill=WHITE,
    )
    dot = w * 0.065
    cy = top + w * 0.73
    draw.ellipse([cx - dot, cy - dot, cx + dot, cy + dot], fill=WHITE)
    return image.resize((size, size), Image.LANCZOS)


def main() -> None:
    assets = APP / "ios" / "App" / "App" / "Assets.xcassets"
    if not assets.exists():
        raise SystemExit("no ios/ project yet: npx cap add ios")
    icon = mark(1024, 0.62)
    icon.save(assets / "AppIcon.appiconset" / "AppIcon-512@2x.png", optimize=True)
    splash = mark(2732, 0.16)
    for name in ("splash-2732x2732.png", "splash-2732x2732-1.png", "splash-2732x2732-2.png"):
        splash.save(assets / "Splash.imageset" / name, optimize=True)
    icon.save(APP / "store" / "icon-1024.png", optimize=True)
    print("icon and launch image written")


if __name__ == "__main__":
    main()
