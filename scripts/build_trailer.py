"""Build the Hexbreaker TRAILER — VOICE-READY (no baked narration), nothing fabricated.

Design (see docs/trailer_vo_script.md for the timed VO lines to record over it):
  - NO baked voice. Visuals + sparse on-screen punch-words carry the story muted; a
    low music bed sits under it with headroom for Alex's voiceover overlay.
  - Cold-open is SYMBOLIC of the field's hallucination problem (a confident check
    that flips to a red X) — clearly generic, not a fake Hexbreaker output.
  - PROOF cuts are the REAL terminal (reused asciinema captures): the self-correction
    CONFIRMED->CONTESTED beat and `hexbreaker verify --hmac` of the committed signed
    NIST 4/4. Stat wall shows only real committed numbers.

Free tools: agg (AGG_BIN=/tmp/agg), ffmpeg, Pillow, numpy (music synth).
    AGG_BIN=/tmp/agg python3 scripts/build_trailer.py --out docs/trailer.mp4
"""
from __future__ import annotations

import argparse
import os
import subprocess
import wave
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont

OUT = Path("/tmp/trailer2_build")
AGG = os.environ.get("AGG_BIN", "agg")
PW = os.environ.get("HEXBREAKER_HMAC_PASSWORD", "hexbreaker-nist-fsm")
W, H, FPS = 1280, 720, 30
COLS, ROWS = 100, 26

BG = (12, 14, 22)
FG = (248, 248, 242)
DIM = (120, 134, 170)
CYAN = (139, 233, 253)
GREEN = (80, 250, 123)
PURPLE = (189, 147, 249)
RED = (255, 85, 95)
YELLOW = (241, 250, 140)
FD = "/usr/share/fonts/truetype/dejavu"


def font(name, size):
    return ImageFont.truetype(f"{FD}/{name}", size)


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def ease(x):
    x = max(0.0, min(1.0, x))
    return x * x * (3 - 2 * x)


def bg(dr, i, base=BG):
    dr.rectangle([0, 0, W, H], fill=base)
    step = 46
    off = (i * 0.5) % step
    for y in range(-step, H + step, step):
        for x in range(-step, W + step, step):
            tw = (np.sin((x + y) * 0.04 + i * 0.05) + 1) / 2
            c = int(20 + tw * 20)
            dr.ellipse([x + off, y + off * 0.5, x + off + 2, y + off * 0.5 + 2],
                       fill=(c, c + 3, c + 10))


def ctext(dr, cx, cy, text, fnt, fill, a=255):
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    bb = ld.textbbox((0, 0), text, font=fnt)
    ld.text((cx - (bb[2] - bb[0]) // 2 - bb[0], cy - (bb[3] - bb[1]) // 2 - bb[1]),
            text, font=fnt, fill=(fill[0], fill[1], fill[2], int(a)))
    return layer


def fdir(seg):
    d = OUT / seg
    d.mkdir(parents=True, exist_ok=True)
    return d


def frames_to_clip(seg, render_fn, secs):
    d = fdir(seg)
    n = int(secs * FPS)
    for i in range(n):
        render_fn(i, n).save(d / f"{i:04d}.png")
    out = OUT / f"{seg}.mp4"
    run(["ffmpeg", "-y", "-framerate", str(FPS), "-i", str(d / "%04d.png"),
         "-c:v", "libx264", "-pix_fmt", "yuv420p", "-r", str(FPS), str(out)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return out, secs


# ---------- segments ----------
def seg_coldopen(secs=8.0):
    f_big = font("DejaVuSans-Bold.ttf", 58)
    f_cap = font("DejaVuSans.ttf", 34)
    f_mono = font("DejaVuSansMono.ttf", 30)

    def draw_mark(img, cx, cy, kind, col, a):
        ov = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        d = ImageDraw.Draw(ov)
        r = 46
        d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(col[0], col[1], col[2], a), width=6)
        if kind == "check":
            d.line([(cx - 22, cy + 2), (cx - 6, cy + 20), (cx + 24, cy - 20)],
                   fill=(col[0], col[1], col[2], a), width=8, joint="curve")
        else:
            d.line([(cx - 20, cy - 20), (cx + 20, cy + 20)], fill=(col[0], col[1], col[2], a), width=8)
            d.line([(cx - 20, cy + 20), (cx + 20, cy - 20)], fill=(col[0], col[1], col[2], a), width=8)
        img.paste(ov, (0, 0), ov)

    def render(i, n):
        t = i / FPS
        img = Image.new("RGB", (W, H), BG)
        dr = ImageDraw.Draw(img)
        bg(dr, i)
        flip = 3.4  # second the verdict flips to wrong
        wrong = t >= flip
        # the "confident finding" line
        a1 = int(255 * ease(t / 0.8))
        line = "FINDING:  malware.exe  —  CONFIRMED"
        col = RED if wrong else GREEN
        # glitch around the flip
        gx = 0
        if abs(t - flip) < 0.5:
            gx = int(np.random.randint(-14, 14))
        img.paste(ctext(dr, W // 2 + gx, H // 2 - 30, line, f_mono, col, a1),
                  (0, 0), ctext(dr, W // 2 + gx, H // 2 - 30, line, f_mono, col, a1))
        draw_mark(img, W // 2 - 330, H // 2 - 30, "cross" if wrong else "check", col, a1)
        if wrong:
            aw = int(255 * ease((t - flip) / 0.5))
            img.paste(ctext(dr, W // 2, H // 2 + 36, "...except it was never there.", f_cap, RED, aw),
                      (0, 0), ctext(dr, W // 2, H // 2 + 36, "...except it was never there.", f_cap, RED, aw))
        # caption
        ac = int(230 * ease((t - flip - 0.6) / 0.8)) if t > flip + 0.6 else 0
        if ac > 0:
            img.paste(ctext(dr, W // 2, H - 90, "AI forensics has a trust problem.", f_big, FG, ac),
                      (0, 0), ctext(dr, W // 2, H - 90, "AI forensics has a trust problem.", f_big, FG, ac))
        return img
    return frames_to_clip("01_coldopen", render, secs)


def seg_lines(seg, lines, secs, accent=RED):
    f = font("DejaVuSans-Bold.ttf", 56)

    def render(i, n):
        t = i / FPS
        img = Image.new("RGB", (W, H), BG)
        dr = ImageDraw.Draw(img)
        bg(dr, i)
        dr.rectangle([95, H // 2 - 95, 103, H // 2 + 95], fill=accent)
        y0 = H // 2 - len(lines) * 42
        for li, (txt, col) in enumerate(lines):
            a = ease((t - li * 0.55) / 0.8)
            if a <= 0:
                continue
            lay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
            ld = ImageDraw.Draw(lay)
            ld.text((135, y0 + li * 84), txt, font=f, fill=(col[0], col[1], col[2], int(255 * a)))
            img.paste(lay, (0, 0), lay)
        return img
    return frames_to_clip(seg, render, secs)


def seg_turn(secs=5.0):
    f_q = font("DejaVuSans-Bold.ttf", 46)
    f_t = font("DejaVuSans-Bold.ttf", 104)

    def render(i, n):
        t = i / FPS
        img = Image.new("RGB", (W, H), BG)
        dr = ImageDraw.Draw(img)
        bg(dr, i)
        aq = ease(t / 0.8) * (1 - ease((t - 2.4) / 0.6))
        if aq > 0:
            img.paste(ctext(dr, W // 2, H // 2 - 80, "What if it were built to catch itself?",
                            f_q, FG, int(255 * aq)), (0, 0),
                      ctext(dr, W // 2, H // 2 - 80, "What if it were built to catch itself?",
                            f_q, FG, int(255 * aq)))
        at = ease((t - 2.4) / 1.0)
        if at > 0:
            dy = int((1 - at) * 30)
            img.paste(ctext(dr, W // 2, H // 2 + 20 + dy, "HEXBREAKER", f_t, CYAN, int(255 * at)),
                      (0, 0), ctext(dr, W // 2, H // 2 + 20 + dy, "HEXBREAKER", f_t, CYAN, int(255 * at)))
            uw = int(560 * at)
            dr.rectangle([W // 2 - uw // 2, H // 2 + 78, W // 2 + uw // 2, H // 2 + 84], fill=PURPLE)
        return img
    return frames_to_clip("03_turn", render, secs)


def proof_cut(seg, cast, title, caption, accent, secs, speed=1.7):
    d = fdir(seg)
    gif = d / "t.gif"
    run([AGG, "--cols", str(COLS), "--rows", str(ROWS), "--theme", "dracula",
         "--font-size", "20", str(cast), str(gif)])
    # backdrop with title + caption baked
    back = d / "back.png"
    img = Image.new("RGB", (W, H), BG)
    dr = ImageDraw.Draw(img)
    bg(dr, 0)
    dr.rectangle([60, 70, W - 60, 118], fill=(22, 25, 36))
    dr.rectangle([60, 70, 68, 118], fill=accent)
    dr.text((90, 82), title, font=font("DejaVuSansMono.ttf", 24), fill=accent)
    cb = font("DejaVuSans-Bold.ttf", 40)
    bb = dr.textbbox((0, 0), caption, font=cb)
    dr.text(((W - (bb[2] - bb[0])) // 2, H - 92), caption, font=cb, fill=FG)
    img.save(back)
    out = OUT / f"{seg}.mp4"
    # speed up the terminal, fit into a window region, overlay on backdrop, hold to secs
    run(["ffmpeg", "-y", "-loop", "1", "-i", str(back), "-i", str(gif),
         "-filter_complex",
         f"[1:v]setpts=PTS/{speed},scale=1100:470:force_original_aspect_ratio=decrease:flags=lanczos[t];"
         f"[0:v][t]overlay=(W-w)/2:150:eof_action=repeat:shortest=0[v];"
         f"[v]trim=0:{secs}[vv]",
         "-map", "[vv]", "-t", f"{secs}", "-c:v", "libx264", "-pix_fmt", "yuv420p",
         "-r", str(FPS), str(out)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return out, secs


def seg_stats(secs=8.0):
    stats = [("4 / 4", "NIST tools recovered (signed)", GREEN),
             ("0 / 80", "baits taken under attack", CYAN),
             ("0.95-0.975", "Forge F1 (normal)", PURPLE),
             ("169", "tests passing", FG),
             ("6", "artifact templates", YELLOW),
             ("100%", "chain + HMAC verified", GREEN)]
    f_n = font("DejaVuSans-Bold.ttf", 60)
    f_l = font("DejaVuSansMono.ttf", 21)
    f_h = font("DejaVuSans-Bold.ttf", 38)
    cols = 3

    def render(i, n):
        t = i / FPS
        img = Image.new("RGB", (W, H), BG)
        dr = ImageDraw.Draw(img)
        bg(dr, i)
        ah = ease(t / 0.7)
        img.paste(ctext(dr, W // 2, 95, "Every number, committed + verifiable.", f_h, FG, int(255 * ah)),
                  (0, 0), ctext(dr, W // 2, 95, "Every number, committed + verifiable.", f_h, FG, int(255 * ah)))
        for si, (num, lab, col) in enumerate(stats):
            r, c = si // cols, si % cols
            cx = c * (W // cols) + W // cols // 2
            cy = 250 + r * 190
            a = ease((t - (0.6 + si * 0.4)) / 0.6)
            if a <= 0:
                continue
            img.paste(ctext(dr, cx, cy, num, f_n, col, int(255 * a)), (0, 0),
                      ctext(dr, cx, cy, num, f_n, col, int(255 * a)))
            img.paste(ctext(dr, cx, cy + 52, lab, f_l, DIM, int(255 * a)), (0, 0),
                      ctext(dr, cx, cy + 52, lab, f_l, DIM, int(255 * a)))
        return img
    return frames_to_clip("06_stats", render, secs)


def seg_close(secs=6.0):
    f_b = font("DejaVuSans-Bold.ttf", 88)
    f_u = font("DejaVuSansMono.ttf", 30)
    f_s = font("DejaVuSans.ttf", 26)

    def render(i, n):
        t = i / FPS
        img = Image.new("RGB", (W, H), BG)
        dr = ImageDraw.Draw(img)
        bg(dr, i)
        a = ease(t / 0.9)
        img.paste(ctext(dr, W // 2, H // 2 - 70, "Miss, don't lie.", f_b, GREEN, int(255 * a)),
                  (0, 0), ctext(dr, W // 2, H // 2 - 70, "Miss, don't lie.", f_b, GREEN, int(255 * a)))
        a2 = ease((t - 1.1) / 0.9)
        if a2 > 0:
            img.paste(ctext(dr, W // 2, H // 2 + 30, "HEXBREAKER", f_u, CYAN, int(255 * a2)),
                      (0, 0), ctext(dr, W // 2, H // 2 + 30, "HEXBREAKER", f_u, CYAN, int(255 * a2)))
            img.paste(ctext(dr, W // 2, H // 2 + 78, "github.com/Alexander-Sorrell-IT/hexbreaker",
                            f_s, DIM, int(220 * a2)), (0, 0),
                      ctext(dr, W // 2, H // 2 + 78, "github.com/Alexander-Sorrell-IT/hexbreaker",
                            f_s, DIM, int(220 * a2)))
        return img
    return frames_to_clip("07_close", render, secs)


def make_music(total, out, turn_at):
    sr = 44100
    t = np.linspace(0, total, int(sr * total), endpoint=False)
    sine = lambda f, a: a * np.sin(2 * np.pi * f * t)
    drone = sine(55, 0.18) + sine(82.41, 0.12) + sine(110, 0.10) + sine(130.81, 0.07)
    drone *= 0.6 + 0.4 * np.sin(2 * np.pi * 0.05 * t)
    pulse = np.zeros_like(t)
    k = 0
    while k * 1.4 < total:
        c = k * 1.4
        env = np.exp(-np.maximum(t - c, 0) * 5) * (t >= c)
        pulse += 0.22 * np.sin(2 * np.pi * 55 * t) * env
        k += 1
    riser = np.zeros_like(t)
    mask = (t > turn_at - 1.8) & (t < turn_at)
    rt = np.clip((t - (turn_at - 1.8)) / 1.8, 0, 1)
    riser = np.where(mask, np.random.randn(len(t)) * 0.05 * rt, 0)
    mix = drone + pulse + riser
    mix /= np.max(np.abs(mix)) + 1e-9
    mix *= 0.5  # headroom for the future voiceover overlay
    fi, fo = int(sr * 1.0), int(sr * 1.5)
    mix[:fi] *= np.linspace(0, 1, fi)
    mix[-fo:] *= np.linspace(1, 0, fo)
    w = wave.open(str(out), "w")
    w.setnchannels(1); w.setsampwidth(2); w.setframerate(sr)
    w.writeframes((mix * 32767).astype("<i2").tobytes())
    w.close()


def xfade(clips, durs, out, trans=0.4):
    inputs = []
    for c in clips:
        inputs += ["-i", str(c)]
    fc = []
    prev = "0:v"
    cum = durs[0]
    for i in range(1, len(clips)):
        off = cum - trans
        lab = f"v{i}"
        fc.append(f"[{prev}][{i}:v]xfade=transition=fade:duration={trans}:offset={off:.3f}[{lab}]")
        prev = lab
        cum += durs[i] - trans
    run(["ffmpeg", "-y", *inputs, "-filter_complex", ";".join(fc),
         "-map", f"[{prev}]", "-r", str(FPS), "-c:v", "libx264", "-pix_fmt", "yuv420p", str(out)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cum


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="docs/trailer.mp4")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    sc_cast = Path("/tmp/demo_build/03_selfcorrect/rec.cast")
    nist_cast = Path("/tmp/demo_build/04_nist/rec.cast")

    clips, durs = [], []
    for c, dd in [
        seg_coldopen(8.0),
        seg_lines("02_stakes", [("A made-up finding isn't a miss.", FG),
                                ("It's a false accusation.", RED)], 6.0),
        seg_turn(5.0),
        proof_cut("04_selfcorrect", sc_cast, "PROOF · runtime self-correction",
                  "It caught itself — in code.", CYAN, 10.0),
        proof_cut("05_nist", nist_cast, "PROOF · real NIST disk (.E01), signed",
                  "Real disk. 4 / 4. Verified on screen.", GREEN, 10.0),
        seg_stats(8.0),
        seg_close(6.0),
    ]:
        clips.append(c)
        durs.append(dd)

    silent = OUT / "silent.mp4"
    total = xfade(clips, durs, silent)
    turn_at = durs[0] + durs[1] - 0.4 * 2 + 2.4  # ~ when HEXBREAKER forms
    music = OUT / "music.wav"
    make_music(total, music, turn_at)
    out = Path(args.out)
    run(["ffmpeg", "-y", "-i", str(silent), "-i", str(music),
         "-map", "0:v", "-map", "1:a", "-c:v", "copy", "-c:a", "aac", "-b:a", "160k",
         "-shortest", "-movflags", "+faststart", str(out)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"TRAILER (voice-ready, no narration): {out}  ({total:.1f}s)")


if __name__ == "__main__":
    main()
