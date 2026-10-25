"""App icons and launch images for iOS and Android: `python3 scripts/icons.py`.

Apple refuses the stock Capacitor icon, and an icon with transparency; Google Play
wants a 512 px icon and an adaptive launcher icon. All are drawn here from one sign:
a red warning triangle with an exclamation mark on dark navy, supersampled for smooth
edges. Needs Pillow (`pip install pillow`). Writes into the ios/ and android/
projects that exist; run after `npx cap add …`.
"""

from __future__ import annotations

import pathlib

from PIL import Image, ImageDraw

APP = pathlib.Path(__file__).resolve().parent.parent
NAVY = (15, 29, 51)
RED = (217, 45, 32)
WHITE = (255, 255, 255)
SS = 4  # supersampling


def draw_sign(draw: ImageDraw.ImageDraw, cx: float, cy: float, w: float) -> None:
    """The sign, `w` wide, centred on (cx, cy)."""
    h = w * 0.88
    top = cy - h / 2
    tri = [(cx, top), (cx + w / 2, top + h), (cx - w / 2, top + h)]
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
    y = top + w * 0.73
    draw.ellipse([cx - dot, y - dot, cx + dot, y + dot], fill=WHITE)


def image(width: int, height: int, scale: float, *, background=NAVY, round_=False) -> Image.Image:
    """The sign `scale` of the shorter side wide, on navy (or transparent, or a navy disc)."""
    W, H = width * SS, height * SS
    transparent = background is None or round_
    canvas = Image.new("RGBA" if transparent else "RGB", (W, H), (0, 0, 0, 0) if transparent else background)
    draw = ImageDraw.Draw(canvas)
    if round_:
        draw.ellipse([0, 0, W - 1, H - 1], fill=NAVY)
    draw_sign(draw, W / 2, H / 2, min(W, H) * scale)
    return canvas.resize((width, height), Image.LANCZOS)


def ios() -> None:
    assets = APP / "ios" / "App" / "App" / "Assets.xcassets"
    if not assets.exists():
        print("ios: no project (npx cap add ios)")
        return
    # No alpha channel: App Store Connect rejects an icon with one.
    image(1024, 1024, 0.62).save(assets / "AppIcon.appiconset" / "AppIcon-512@2x.png", optimize=True)
    splash = image(2732, 2732, 0.16)
    for name in ("splash-2732x2732.png", "splash-2732x2732-1.png", "splash-2732x2732-2.png"):
        splash.save(assets / "Splash.imageset" / name, optimize=True)
    image(1024, 1024, 0.62).save(APP / "store" / "icon-1024.png", optimize=True)
    print("ios: icon and launch image written")


#: Launcher icon side in px per density (48 dp), adaptive layer side (108 dp).
DENSITIES = {"mdpi": 1.0, "hdpi": 1.5, "xhdpi": 2.0, "xxhdpi": 3.0, "xxxhdpi": 4.0}


def android() -> None:
    res = APP / "android" / "app" / "src" / "main" / "res"
    if not res.exists():
        print("android: no project (npx cap add android)")
        return
    for density, k in DENSITIES.items():
        side, layer = round(48 * k), round(108 * k)
        folder = res / f"mipmap-{density}"
        image(side, side, 0.62).save(folder / "ic_launcher.png", optimize=True)
        image(side, side, 0.56, round_=True).save(folder / "ic_launcher_round.png", optimize=True)
        # Adaptive foreground: the launcher masks the 108 dp layer to a shape, and
        # only the central 66 dp are safe -- the sign stays inside them.
        image(layer, layer, 0.42, background=None).save(folder / "ic_launcher_foreground.png", optimize=True)
    for splash in res.glob("drawable*/splash.png"):
        w, h = Image.open(splash).size
        image(w, h, 0.28).save(splash, optimize=True)
    # Google Play listing icon: 512 x 512, 32-bit PNG.
    image(512, 512, 0.62).convert("RGBA").save(APP / "store" / "play-icon-512.png", optimize=True)
    print("android: launcher icons, launch images and the Play icon written")


if __name__ == "__main__":
    (APP / "store").mkdir(exist_ok=True)
    ios()
    android()
