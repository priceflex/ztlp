"""Generate ZTLP macOS icon assets from the two source PNGs.

AppIcon  <- logo.png (full-color shield + network), cropped to its content,
            centered on a white rounded-square (macOS 'squircle'-ish) tile.
MenuBar  <- shield.png (navy shield-lock), converted to a black-on-transparent
            TEMPLATE image (macOS tints it for light/dark menu bars).
"""
from PIL import Image, ImageDraw, ImageChops
import json, os, sys

SRC = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(SRC, "..", "ZTLP", "Resources", "Assets.xcassets")
APP = f"{ROOT}/AppIcon.appiconset"
MENU = f"{ROOT}/MenuBarIcon.imageset"
PREVIEW = "/tmp/ztlp-icon-preview"
os.makedirs(PREVIEW, exist_ok=True)


def content_bbox(im, thresh=245):
    """Bounding box of non-white / non-transparent content."""
    rgba = im.convert("RGBA")
    bg = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
    flat = Image.alpha_composite(bg, rgba).convert("L")
    mask = flat.point(lambda v: 255 if v < thresh else 0)
    return mask.getbbox()


# ---------------- App icon ----------------
logo = Image.open(f"{SRC}/ZTLP_Logo.png").convert("RGBA")
bb = content_bbox(logo)
art = logo.crop(bb)
# make the near-white background of the source transparent so it sits on our tile
px = art.load()
for y in range(art.height):
    for x in range(art.width):
        r, g, b, a = px[x, y]
        if r > 248 and g > 248 and b > 248:
            px[x, y] = (255, 255, 255, 0)

MASTER = 1024
tile = Image.new("RGBA", (MASTER, MASTER), (0, 0, 0, 0))
# Apple macOS icon grid: content tile ~824px inset 100px, corner radius ~185
inset, radius = 100, 185
mask = Image.new("L", (MASTER, MASTER), 0)
ImageDraw.Draw(mask).rounded_rectangle([inset, inset, MASTER - inset, MASTER - inset], radius=radius, fill=255)
bgtile = Image.new("RGBA", (MASTER, MASTER), (255, 255, 255, 255))
tile.paste(bgtile, (0, 0), mask)
# fit art into ~80% of the tile
avail = int((MASTER - 2 * inset) * 0.86)
scale = min(avail / art.width, avail / art.height)
art_s = art.resize((int(art.width * scale), int(art.height * scale)), Image.LANCZOS)
ox = (MASTER - art_s.width) // 2
oy = (MASTER - art_s.height) // 2
tile.alpha_composite(art_s, (ox, oy))
# keep everything inside the rounded tile
tile.putalpha(ImageChops.multiply(tile.getchannel("A"), mask))

images = []
for size in (16, 32, 128, 256, 512):
    for scale_i in (1, 2):
        px_size = size * scale_i
        name = f"icon_{size}x{size}{'@2x' if scale_i == 2 else ''}.png"
        tile.resize((px_size, px_size), Image.LANCZOS).save(f"{APP}/{name}")
        images.append({"filename": name, "idiom": "mac", "scale": f"{scale_i}x", "size": f"{size}x{size}"})
json.dump({"images": images, "info": {"author": "xcode", "version": 1}}, open(f"{APP}/Contents.json", "w"), indent=2)

# ---------------- Menu bar template ----------------
shield = Image.open(f"{SRC}/ZTLP_Shield_Lock_Icon.png").convert("RGBA")
sb = content_bbox(shield, thresh=200)
sh = shield.crop(sb)
# source has a transparent bg with black RGB underneath: flatten on white first
sh = Image.alpha_composite(Image.new("RGBA", sh.size, (255, 255, 255, 255)), sh)
# template: dark navy pixels -> opaque black; white/light -> transparent.
# luminance drives alpha so edges stay anti-aliased.
L = sh.convert("L")
alpha = L.point(lambda v: max(0, min(255, int((235 - v) * 255 / 200))))
tmpl = Image.new("RGBA", sh.size, (0, 0, 0, 255))
tmpl.putalpha(alpha)


def menu_png(height_px):
    w = round(tmpl.width * height_px / tmpl.height)
    return tmpl.resize((w, height_px), Image.LANCZOS)

# 18pt is the standard menu-bar glyph height
m1, m2 = menu_png(18), menu_png(36)
for f in os.listdir(MENU):
    if f.endswith(".png"):
        os.remove(f"{MENU}/{f}")
m1.save(f"{MENU}/menubar.png")
m2.save(f"{MENU}/menubar@2x.png")
json.dump({
    "images": [
        {"filename": "menubar.png", "idiom": "mac", "scale": "1x"},
        {"filename": "menubar@2x.png", "idiom": "mac", "scale": "2x"},
    ],
    "info": {"author": "xcode", "version": 1},
    "properties": {"template-rendering-intent": "template"},
}, open(f"{MENU}/Contents.json", "w"), indent=2)

# ---------------- Preview sheet ----------------
sheet = Image.new("RGB", (900, 420), (235, 235, 235))
d = ImageDraw.Draw(sheet)
sheet.paste(tile.resize((256, 256), Image.LANCZOS), (20, 20), tile.resize((256, 256), Image.LANCZOS))
x = 300
for s in (128, 64, 32, 16):
    t = tile.resize((s, s), Image.LANCZOS)
    sheet.paste(t, (x, 20), t)
    x += s + 20
d.text((20, 290), "App icon (Finder/Dock/notary dialogs): 256 / 128 / 64 / 32 / 16", fill=(0, 0, 0))
# menu bars at 2x (36px tall glyph in a 48px bar), light + dark
for i, bar in enumerate(((246, 246, 246), (30, 30, 30))):
    y = 320 + i * 50
    d.rectangle([20, y, 860, y + 44], fill=bar)
    # tint template to the menu-bar foreground color, like macOS does
    tinted = Image.new("RGBA", m2.size, (0, 0, 0, 255) if i == 0 else (255, 255, 255, 255))
    tinted.putalpha(m2.getchannel("A"))
    sheet.paste(tinted, (400, y + 4), tinted)
    dim = tinted.copy(); dim.putalpha(m2.getchannel("A").point(lambda v: v * 45 // 100))
    sheet.paste(dim, (460, y + 4), dim)
    d.text((30, y + 15), ("light" if i == 0 else "dark") + " menu bar @2x:  ready | not ready (dimmed)", fill=(0, 0, 0) if i == 0 else (230, 230, 230))
sheet.save(f"{PREVIEW}/icons-preview.png")
print("ok", tile.size, m1.size, m2.size)
