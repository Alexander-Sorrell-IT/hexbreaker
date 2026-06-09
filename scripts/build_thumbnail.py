"""Render the YouTube/Devpost thumbnail for the Hexbreaker demo (1280x720).

Honesty rule (same as trailer/demo): every number on the card is committed +
reproducible — 4/4 NIST, 0/80 baits, F1 0.95-0.975. No rounding up, no "95%".

    python scripts/build_thumbnail.py --out docs/thumbnail.png
"""
from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 720
FONT = "/usr/share/fonts/truetype/dejavu"
MONO = "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf"

# dracula-ish palette (matches the demo terminal)
BG_TOP = (24, 18, 33)      # deep aubergine
BG_BOT = (13, 10, 20)
INK = (248, 248, 242)
MUTE = (148, 142, 168)
GREEN = (80, 250, 123)
RED = (255, 85, 85)
CYAN = (139, 233, 253)
PURPLE = (189, 147, 249)


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(f"{FONT}/{name}", size)


def vgradient(img: Image.Image) -> None:
    px = img.load()
    for y in range(H):
        t = y / H
        r = int(BG_TOP[0] + (BG_BOT[0] - BG_TOP[0]) * t)
        g = int(BG_TOP[1] + (BG_BOT[1] - BG_TOP[1]) * t)
        b = int(BG_TOP[2] + (BG_BOT[2] - BG_TOP[2]) * t)
        for x in range(W):
            px[x, y] = (r, g, b)


def center(d, cx, y, text, f, fill):
    w = d.textlength(text, font=f)
    d.text((cx - w / 2, y), text, font=f, fill=fill)
    return w


def build(out: Path) -> None:
    img = Image.new("RGB", (W, H))
    vgradient(img)
    d = ImageDraw.Draw(img)

    # top eyebrow
    eb = font("DejaVuSansMono.ttf", 26)
    center(d, W / 2, 64, "AUTONOMOUS DFIR  ·  SANS FIND EVIL! 2026", eb, MUTE)

    # the flip motif: CONFIRMED -> CONTESTED (the whole thesis in one line)
    flip = font("DejaVuSansMono-Bold.ttf", 34)
    seg = [("✓ CONFIRMED", GREEN), ("   ⟶   ", MUTE), ("✗ CONTESTED", RED)]
    total = sum(d.textlength(t, font=flip) for t, _ in seg)
    x = W / 2 - total / 2
    for t, c in seg:
        d.text((x, 118), t, font=flip, fill=c)
        x += d.textlength(t, font=flip)

    # wordmark
    big = font("DejaVuSans-Bold.ttf", 150)
    center(d, W / 2, 178, "HEXBREAKER", big, INK)

    # accent rule
    d.rectangle([W / 2 - 220, 352, W / 2 + 220, 358], fill=PURPLE)

    # tagline
    tag = font("DejaVuSerif-BoldItalic.ttf", 60)
    center(d, W / 2, 372, "“Miss, don’t lie.”", tag, CYAN)

    # proof strip — three committed numbers
    cards = [("4 / 4", "deleted tools recovered\non the real NIST disk", GREEN),
             ("0 / 80", "planted baits taken\nin adversarial runs", GREEN),
             ("F1 .95–.975", "normal-mode accuracy\nhash-chained + signed", CYAN)]
    num_f = font("DejaVuSans-Bold.ttf", 52)
    sub_f = font("DejaVuSans.ttf", 24)
    cw, gap = 360, 32
    total_w = cw * 3 + gap * 2
    x0 = W / 2 - total_w / 2
    cy = 478
    for i, (num, sub, col) in enumerate(cards):
        x = x0 + i * (cw + gap)
        d.rounded_rectangle([x, cy, x + cw, cy + 168], radius=18,
                            fill=(34, 28, 46), outline=(58, 50, 74), width=2)
        center(d, x + cw / 2, cy + 24, num, num_f, col)
        for j, line in enumerate(sub.split("\n")):
            center(d, x + cw / 2, cy + 96 + j * 30, line, sub_f, MUTE)

    img.save(out)
    print(f"wrote {out} ({W}x{H})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="docs/thumbnail.png")
    a = ap.parse_args()
    build(Path(a.out))
