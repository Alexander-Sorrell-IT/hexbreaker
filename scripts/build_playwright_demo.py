"""Record a REAL demo video with Playwright — browser-captured animated terminal.

Unlike the flat agg->gif render, this plays our genuine asciinema recordings in the
asciinema-player inside Chromium and lets Playwright capture the live, animated
playback (typing, cursor, ANSI colours) as actual browser video. Then free neural
TTS narration is muxed per beat and the beats are concatenated.

Every frame is our REAL recorded session (the .cast files captured from the live
PTY running Hexbreaker) — animated and screen-recorded, a true demo video.

Deps (all free, installed this session): playwright + chromium, edge-tts, ffmpeg.
    python scripts/build_playwright_demo.py --out docs/demo.mp4
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from playwright.sync_api import sync_playwright

BUILD = Path("/tmp/demo_build")          # holds NN_*/rec.cast from build_screencast_demo
WEB = Path("/tmp/demo_web")              # vendored asciinema-player.{min.js,css}
VOICE = "en-US-AndrewNeural"
W, H = 1280, 720

# Per-beat narration (the cast files are already the real recorded sessions).
NARR = {
    "01_intro": "Find Evil asks an AI agent to triage a forensic image without "
        "hallucinating. The hard part isn't finding artifacts. It's not inventing "
        "them. Hexbreaker is a generative benchmark plus a five-role adversarial "
        "court whose anti-hallucination guarantees live in Python, not a prompt.",
    "02_generate": "One seed deterministically produces a full case: real tool "
        "outputs, an answer key, and a planted artifact built to bait the agent into "
        "a false confirmation. Six artifact types ship today.",
    "03_selfcorrect": "Watch the safeguard fire. The defender, an LLM, confirms the "
        "artifact citing a single tool. That's the bait-taking failure mode. But a "
        "deterministic Python judge overrides it, downgrading confirmed to contested "
        "in code, and emits no finding. The architecture stopped the model from "
        "over-claiming, and it's recorded in a signed, hash-chained transcript.",
    "04_nist": "Now the real thing. The NIST Hacking Case, an actual seized disk "
        "image. The court runs on the real recycle-bin evidence and recovers all "
        "four of the attacker's deleted tools. Four of four, zero false positives. "
        "Honestly scoped to the recycle-bin question family, with no answers injected.",
    "05_close": "And when it fails, it fails the right way. Across eighty adversarial "
        "runs, every failure is a miss. Zero false confirmations, zero baits taken. "
        "It would rather say nothing than lie. An agent you can trust because it's "
        "built to be caught when it's wrong.",
}

PAGE = """<!doctype html><html><head><meta charset=utf-8>
<link rel=stylesheet href="file://{css}">
<style>
  html,body{{margin:0;background:#0b0e14;height:100%;overflow:hidden;
    font-family:'DejaVu Sans',sans-serif}}
  .wrap{{padding:28px 36px}}
  .bar{{display:flex;align-items:center;gap:10px;margin-bottom:14px}}
  .dot{{width:13px;height:13px;border-radius:50%}}
  .r{{background:#ff5f56}}.y{{background:#ffbd2e}}.g{{background:#27c93f}}
  .title{{color:#8b95a7;font-size:15px;margin-left:10px;letter-spacing:.3px}}
  .badge{{margin-left:auto;color:#e06c75;font-weight:700;font-size:15px;
    letter-spacing:1px}}
  #term{{box-shadow:0 18px 60px rgba(0,0,0,.6);border-radius:10px;overflow:hidden}}
  .ap-terminal{{padding:16px !important}}
</style></head>
<body><div class=wrap>
  <div class=bar><span class="dot r"></span><span class="dot y"></span>
    <span class="dot g"></span><span class=title>hexbreaker — {title}</span>
    <span class=badge>FIND EVIL ◆ HEXBREAKER</span></div>
  <div id=term></div>
</div>
<script src="file://{js}"></script>
<script>
  AsciinemaPlayer.create("file://{cast}", document.getElementById('term'),
    {{autoPlay:true, cols:{cols}, rows:{rows}, fit:'width', theme:'dracula',
      fontSize:'18px', idleTimeLimit:1.2}});
</script></body></html>"""

TITLES = {"01_intro":"adversarial DFIR triage", "02_generate":"forge: generate a case",
    "03_selfcorrect":"court: the judge self-corrects", "04_nist":"real NIST .E01 — 4/4",
    "05_close":"miss, don't lie"}


def cast_dims(cast: Path):
    head = json.loads(cast.read_text().splitlines()[0])
    return head.get("width", 100), head.get("height", 28)


def cast_dur(cast: Path) -> float:
    last = 0.0
    for ln in cast.read_text().splitlines()[1:]:
        if ln.strip().startswith("["):
            last = max(last, json.loads(ln)[0])
    return last


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def record_beat(pw, beat_dir: Path):
    bid = beat_dir.name
    cast = beat_dir / "rec.cast"
    cols, rows = cast_dims(cast)
    play_dur = cast_dur(cast)
    html = beat_dir / "page.html"
    html.write_text(PAGE.format(css=WEB / "asciinema-player.css",
        js=WEB / "asciinema-player.min.js", cast=cast, cols=cols, rows=rows,
        title=TITLES.get(bid, bid), value="x"))

    vdir = beat_dir / "vid"; vdir.mkdir(exist_ok=True)
    browser = pw.chromium.launch(args=["--no-sandbox", "--disable-gpu",
        "--force-color-profile=srgb", "--autoplay-policy=no-user-gesture-required"])
    ctx = browser.new_context(viewport={"width": W, "height": H},
        record_video_dir=str(vdir), record_video_size={"width": W, "height": H})
    page = ctx.new_page()
    page.goto(f"file://{html}")
    page.wait_for_timeout(int((play_dur + 1.2) * 1000))  # let the cast play out
    ctx.close(); browser.close()
    webm = next(vdir.glob("*.webm"))

    # narration
    mp3 = beat_dir / "narration.mp3"
    run(["python3", "-m", "edge_tts", "--voice", VOICE, "--text", NARR[bid],
         "--write-media", str(mp3)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    adur = float(subprocess.check_output(["ffprobe", "-v", "error", "-show_entries",
        "format=duration", "-of", "csv=p=0", str(mp3)]).decode().strip())

    # beat = max(video, narration); loop last frame of video to fill if narration longer
    beat = beat_dir / "beat.mp4"
    dur = max(play_dur + 1.2, adur) + 0.4
    run(["ffmpeg", "-y", "-i", str(webm), "-i", str(mp3),
         "-filter_complex", f"[0:v]tpad=stop_mode=clone:stop_duration={dur}[v]",
         "-map", "[v]", "-map", "1:a:0", "-t", f"{dur:.2f}",
         "-c:v", "libx264", "-c:a", "aac", "-pix_fmt", "yuv420p", "-r", "30",
         "-movflags", "+faststart", str(beat)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return beat


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="docs/demo.mp4")
    ap.add_argument("--beats", default="01_intro,02_generate,03_selfcorrect,04_nist,05_close")
    args = ap.parse_args()

    want = args.beats.split(",")
    beats = []
    with sync_playwright() as pw:
        for bid in want:
            bdir = BUILD / bid
            if not (bdir / "rec.cast").exists():
                print(f"[skip] {bid}: no rec.cast"); continue
            print(f"[record] {bid} ...", flush=True)
            beats.append(record_beat(pw, bdir))

    listf = BUILD / "concat.txt"
    listf.write_text("".join(f"file '{b.resolve()}'\n" for b in beats))
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(listf),
         "-c:v", "libx264", "-c:a", "aac", "-pix_fmt", "yuv420p", "-r", "30",
         "-movflags", "+faststart", str(out)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    d = subprocess.check_output(["ffprobe", "-v", "error", "-show_entries",
        "format=duration", "-of", "csv=p=0", str(out)]).decode().strip()
    print(f"\nDONE: {out}  ({float(d):.1f}s, {W}x{H})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
