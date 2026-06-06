"""Video inspector — lets a text model 'watch' a video by turning it into readable artifacts.

Produces, for any mp4:
  1. metadata (duration, resolution, fps, codecs)
  2. SCENE frames  — one full-res PNG at each detected scene change (read these to see
     the distinct screens, incl. legible terminal text)
  3. CONTACT sheets — labeled grids sampling the whole video at a fixed interval (flow)
  4. TRANSCRIPT    — the narration, transcribed with timestamps via faster-whisper
  5. report.md     — a storyboard interleaving scenes + transcript on one timeline

Usage:
    python3 scripts/inspect_video.py docs/demo.mp4 --out /tmp/inspect_demo --interval 3
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def probe(v: Path) -> dict:
    out = sh(["ffprobe", "-v", "error", "-show_entries",
              "format=duration:stream=codec_type,codec_name,width,height,r_frame_rate,bit_rate",
              "-of", "json", str(v)]).stdout
    return json.loads(out)


def grab(v: Path, t: float, out: Path):
    sh(["ffmpeg", "-y", "-ss", f"{t:.2f}", "-i", str(v), "-frames:v", "1", str(out)])


def scene_times(v: Path, thresh: float = 0.30) -> list[float]:
    r = sh(["ffmpeg", "-i", str(v), "-vf", f"select='gt(scene,{thresh})',showinfo",
            "-f", "null", "-"])
    times = [float(m) for m in re.findall(r"pts_time:([0-9.]+)", r.stderr)]
    return times


def contact_sheet(frames: list[tuple[float, Path]], out: Path, cols=4, tile_w=460):
    if not frames:
        return
    imgs = []
    for t, p in frames:
        if not p.exists():
            continue
        im = Image.open(p).convert("RGB")
        h = int(im.height * tile_w / im.width)
        im = im.resize((tile_w, h))
        d = ImageDraw.Draw(im)
        try:
            fnt = ImageFont.truetype(FONT, 22)
        except Exception:
            fnt = ImageFont.load_default()
        label = f"{t:0.1f}s"
        d.rectangle([0, 0, 84, 30], fill=(0, 0, 0))
        d.text((6, 4), label, fill=(255, 230, 80), font=fnt)
        imgs.append(im)
    if not imgs:
        return
    tile_h = max(im.height for im in imgs)
    rows = (len(imgs) + cols - 1) // cols
    sheet = Image.new("RGB", (cols * tile_w + (cols + 1) * 6, rows * tile_h + (rows + 1) * 6),
                      (34, 34, 40))
    for i, im in enumerate(imgs):
        r, c = i // cols, i % cols
        x = 6 + c * (tile_w + 6)
        y = 6 + r * (tile_h + 6)
        sheet.paste(im, (x, y))
    sheet.save(out)


def transcribe(v: Path, work: Path) -> list[dict]:
    wav = work / "audio.wav"
    sh(["ffmpeg", "-y", "-i", str(v), "-ar", "16000", "-ac", "1", str(wav)])
    try:
        from faster_whisper import WhisperModel
    except Exception as e:
        return [{"start": 0, "end": 0, "text": f"(faster-whisper unavailable: {e})"}]
    model = WhisperModel("base", device="cpu", compute_type="int8")
    segments, _info = model.transcribe(str(wav), vad_filter=True)
    return [{"start": round(s.start, 1), "end": round(s.end, 1), "text": s.text.strip()}
            for s in segments]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("video")
    ap.add_argument("--out", default="/tmp/inspect")
    ap.add_argument("--interval", type=float, default=3.0)
    ap.add_argument("--no-asr", action="store_true")
    args = ap.parse_args()

    v = Path(args.video)
    out = Path(args.out)
    (out / "scenes").mkdir(parents=True, exist_ok=True)
    (out / "interval").mkdir(parents=True, exist_ok=True)

    meta = probe(v)
    dur = float(meta["format"]["duration"])
    print(f"== {v} ==  duration={dur:.1f}s")
    for s in meta["streams"]:
        print(f"  {s.get('codec_type')}: {s.get('codec_name')} "
              f"{s.get('width','')}x{s.get('height','')} {s.get('r_frame_rate','')}")

    # scene frames (distinct screens)
    sc = scene_times(v)
    sc = [0.5] + sc  # always include the opening
    print(f"\nscene changes @ {[round(t,1) for t in sc]}")
    scene_frames = []
    for i, t in enumerate(sc):
        p = out / "scenes" / f"scene_{i:02d}_{t:06.1f}s.png"
        grab(v, t, p)
        scene_frames.append((t, p))

    # interval frames -> contact sheets
    iv = []
    t = 0.0
    while t < dur:
        p = out / "interval" / f"t_{t:06.1f}.png"
        grab(v, t, p)
        iv.append((t, p))
        t += args.interval
    per = 16
    for si in range(0, len(iv), per):
        contact_sheet(iv[si:si + per], out / f"contact_{si // per:02d}.png")
    n_sheets = (len(iv) + per - 1) // per
    print(f"contact sheets: {n_sheets}  (interval {args.interval}s, {len(iv)} frames)")

    # transcript
    segs = [] if args.no_asr else transcribe(v, out)

    # report
    lines = [f"# Inspection: {v}", "",
             f"- duration: {dur:.1f}s",
             f"- scene frames: {len(scene_frames)} (out/scenes/)",
             f"- contact sheets: {n_sheets} (out/contact_NN.png)", "",
             "## Narration transcript (faster-whisper)", ""]
    for s in segs:
        lines.append(f"- [{s['start']:>5}-{s['end']:<5}] {s['text']}")
    lines += ["", "## Scene frames", ""]
    for t, p in scene_frames:
        lines.append(f"- {t:0.1f}s  ->  {p}")
    (out / "report.md").write_text("\n".join(lines))
    print(f"\nreport: {out / 'report.md'}")
    print("transcript:")
    for s in segs:
        print(f"  [{s['start']:>5}-{s['end']:<5}] {s['text']}")


if __name__ == "__main__":
    main()
