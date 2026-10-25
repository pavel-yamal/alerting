"""App icon and launch image for iOS (and Android later): `python3 scripts/icons.py`.

Apple refuses the stock Capacitor icon, and a store icon with transparency. This
draws a white shield with an exclamation mark on a red gradient -- a signed, trusted
alert -- with a soft shadow under the shield, supersampled for smooth edges. iOS 18
also gets its dark and tinted variants, and the launch image a light and a dark one.
Needs Pillow (`pip install pillow`). Writes into the generated ios/ project; run
after `npx cap add ios`.
"""

from __future__ import annotations

import json
import pathlib

from PIL import Image, ImageChops, ImageDraw, ImageFilter

APP = pathlib.Path(__file__).resolve().parent.parent
RED_TOP, RED_BOTTOM = (255, 95, 87), (214, 32, 52)
WHITE, PAPER = (255, 255, 255), (236, 238, 244)
GREY_TOP, BLACK = (44, 44, 46), (0, 0, 0)
LIGHT_BG = (242, 242, 247)   # the app's own background (app.css --bg)

Colour = tuple[int, int, int]


def gradient(size: int, top: Colour, bottom: Colour) -> Image.Image:
    column = Image.new("RGB", (1, 256))
    for y in range(256):
        column.putpixel((0, y), tuple(round(a + (b - a) * y / 255) for a, b in zip(top, bottom)))
    return column.resize((size, size), Image.BICUBIC)


def bezier(p0, p1, p2, p3, n: int = 64) -> list[tuple[float, float]]:
    out = []
    for i in range(n + 1):
        t = i / n
        u = 1 - t
        out.append(tuple(u**3 * a + 3 * u * u * t * b + 3 * u * t * t * c + t**3 * d
                         for a, b, c, d in zip(p0, p1, p2, p3)))
    return out


def shield() -> list[tuple[float, float]]:
    """The outline in a box 1 wide and 1.12 tall: left half down, mirrored back up."""
    half = (bezier((0.5, 0.0), (0.36, 0.07), (0.16, 0.11), (0.0, 0.12))
            + bezier((0.0, 0.12), (0.0, 0.30), (0.0, 0.42), (0.0, 0.52))
            + bezier((0.0, 0.52), (0.0, 0.82), (0.26, 1.02), (0.5, 1.12)))
    return half + [(1 - x, y) for x, y in reversed(half)]


def icon(size: int, bg: tuple[Colour, Colour], body: tuple[Colour, Colour],
         mark: tuple[Colour, Colour], shadow: float = 0.28, glow: int = 28) -> Image.Image:
    s = size * 2
    image = gradient(s, *bg)
    # A faint light from above, as on Apple's own icons.
    light = Image.new("L", (s, s), 0)
    ImageDraw.Draw(light).ellipse([-s * 0.3, -s * 0.8, s * 1.3, s * 0.4], fill=glow)
    light = light.filter(ImageFilter.GaussianBlur(s * 0.12))
    image = Image.composite(Image.new("RGB", (s, s), WHITE), image, light)

    w = s * 0.54
    x0, y0 = (s - w) / 2, (s - w * 1.12) / 2 + s * 0.01
    outline = Image.new("L", (s, s), 0)
    ImageDraw.Draw(outline).polygon([(x0 + x * w, y0 + y * w) for x, y in shield()], fill=255)
    # Blur and threshold: rounds the corners the outline has.
    outline = outline.filter(ImageFilter.GaussianBlur(s * 0.012)).point(lambda v: 255 if v > 128 else 0)
    outline = outline.filter(ImageFilter.GaussianBlur(1.5))
    drop = ImageChops.offset(outline.filter(ImageFilter.GaussianBlur(s * 0.03)), 0, int(s * 0.025))
    image = Image.composite(Image.new("RGB", (s, s), BLACK), image, drop.point(lambda v: int(v * shadow)))
    image = Image.composite(gradient(s, *body), image, outline)

    sign = Image.new("L", (s, s), 0)
    draw = ImageDraw.Draw(sign)
    bar = w * 0.15
    draw.rounded_rectangle([s / 2 - bar / 2, y0 + w * 0.24, s / 2 + bar / 2, y0 + w * 0.66], radius=bar / 2, fill=255)
    dot, cy = bar * 0.58, y0 + w * 0.84
    draw.ellipse([s / 2 - dot, cy - dot, s / 2 + dot, cy + dot], fill=255)
    image = Image.composite(gradient(s, *mark), image, sign)
    return image.resize((size, size), Image.LANCZOS)


def splash(tile: Image.Image, background: Colour, size: int = 2732, side: int = 300) -> Image.Image:
    """The icon, as a rounded tile, in the middle of a plain screen."""
    image = Image.new("RGB", (size, size), background)
    small = tile.resize((side, side), Image.LANCZOS)
    corners = Image.new("L", (side * 4, side * 4), 0)
    ImageDraw.Draw(corners).rounded_rectangle([0, 0, side * 4 - 1, side * 4 - 1], radius=side * 4 * 0.225, fill=255)
    image.paste(small, ((size - side) // 2, (size - side) // 2), corners.resize((side, side), Image.LANCZOS))
    return image


def main() -> None:
    assets = APP / "ios" / "App" / "App" / "Assets.xcassets"
    if not assets.exists():
        raise SystemExit("no ios/ project yet: npx cap add ios")
    light = icon(1024, (RED_TOP, RED_BOTTOM), (WHITE, PAPER), (RED_TOP, RED_BOTTOM))
    dark = icon(1024, (GREY_TOP, BLACK), (RED_TOP, RED_BOTTOM), (WHITE, PAPER), shadow=0.5, glow=18)
    # Tinted: iOS keeps only the brightness and colours it with the person's tint.
    tinted = icon(1024, (BLACK, BLACK), (WHITE, (200, 200, 200)), ((40, 40, 40), (40, 40, 40)), shadow=0, glow=0).convert("L")

    icons = assets / "AppIcon.appiconset"
    light.save(icons / "AppIcon-512@2x.png", optimize=True)
    dark.save(icons / "AppIcon-dark.png", optimize=True)
    tinted.save(icons / "AppIcon-tinted.png", optimize=True)
    entry = {"idiom": "universal", "platform": "ios", "size": "1024x1024"}
    (icons / "Contents.json").write_text(json.dumps({"images": [
        {"filename": "AppIcon-512@2x.png", **entry},
        {"appearances": [{"appearance": "luminosity", "value": "dark"}], "filename": "AppIcon-dark.png", **entry},
        {"appearances": [{"appearance": "luminosity", "value": "tinted"}], "filename": "AppIcon-tinted.png", **entry},
    ], "info": {"author": "xcode", "version": 1}}, indent=2) + "\n")

    launch = assets / "Splash.imageset"
    images = []
    for suffix, background, look in (("", LIGHT_BG, None), ("-dark", BLACK, "dark")):
        picture = splash(light, background)
        for scale, name in (("1x", "-2"), ("2x", "-1"), ("3x", "")):
            filename = f"splash-2732x2732{suffix}{name}.png"
            picture.save(launch / filename, optimize=True)
            item = {"idiom": "universal", "filename": filename, "scale": scale}
            if look:
                item["appearances"] = [{"appearance": "luminosity", "value": look}]
            images.append(item)
    (launch / "Contents.json").write_text(json.dumps({"images": images, "info": {"version": 1, "author": "xcode"}}, indent=2) + "\n")

    light.save(APP / "store" / "icon-1024.png", optimize=True)
    print("icon (light, dark, tinted) and launch image (light, dark) written")


if __name__ == "__main__":
    main()
