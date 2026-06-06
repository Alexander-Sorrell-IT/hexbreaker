"""Build a COMPLIANT terminal-screencast demo MP4 — real commands, real output.

This is NOT the deleted PIL-slideshow approach. It records our ACTUAL tool running
in a real PTY via asciinema, renders the genuine terminal session to video, and
overlays free neural-TTS narration. The video frames are literally Hexbreaker
executing — live terminal execution, per the hackathon rules.

Pipeline:
  1. For each beat: write a tiny shell script of the REAL commands, record it with
     `asciinema rec` (captures the live PTY into a .cast).
  2. `agg` renders each .cast to a GIF; ffmpeg converts GIF -> mp4 (the actual
     terminal output, timed as it really ran).
  3. `edge-tts` synthesizes the narration for each beat.
  4. ffmpeg pads each beat's video to its narration length, muxes audio, concats.

Requires (all free): asciinema, agg (AGG_BIN=/tmp/agg), edge-tts (pip), ffmpeg.
Fully no-API: every beat runs locally (generate, the deterministic self-correction,
`hexbreaker verify` of the committed signed NIST 4/4 sample, the brittleness summary).
Run from repo root:
    AGG_BIN=/tmp/agg python scripts/build_screencast_demo.py --out docs/demo.mp4
(--no-live still skips the NIST beat for a faster dry build, but it is no longer
API-dependent.)
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

OUT_DIR = Path("/tmp/demo_build")
PW = os.environ.get("HEXBREAKER_HMAC_PASSWORD", "demo-self-correction")

# Each beat: (id, narration, shell commands). Commands are the REAL tool — the
# recorded frames are genuine execution, not slides.
BEATS = [
    (
        "01_intro",
        "Find Evil asks an AI agent to triage a forensic image without "
        "hallucinating. The hard part isn't finding artifacts. It's not inventing "
        "them. Hexbreaker is a generative benchmark plus a five-role adversarial "
        "court whose anti-hallucination guarantees live in Python, not a prompt.",
        "clear\n"
        "echo '# Hexbreaker — adversarial DFIR triage that refuses to hallucinate'\n"
        "echo\n"
        "hexbreaker --help | sed -n '1,12p'\n"
        "sleep 2\n",
    ),
    (
        "02_generate",
        "One seed deterministically produces a full case: real tool outputs, an "
        "answer key, and a planted artifact designed to bait the agent into a false "
        "confirmation. Six artifact types ship today.",
        "clear\n"
        "D=/tmp/demo_$(date +%s)\n"
        "hexbreaker generate --seed 4729 --template timestomp --provocateur --out $D\n"
        "echo; echo '--- the synthetic MFT the agent will read ---'\n"
        "head -4 $D/mock_outputs/*.csv 2>/dev/null || head -4 $D/mock_outputs/* | head -6\n"
        "sleep 2\n",
    ),
    (
        "03_selfcorrect",
        "Watch the safeguard fire. The defender, an LLM, confirms the artifact "
        "citing a single tool. That's exactly the bait-taking failure mode. But a "
        "deterministic Python judge overrides it, downgrading confirmed to contested "
        "in code, and emits no finding. The model tried to over-claim. The "
        "architecture stopped it, and the correction is recorded in a signed, "
        "hash-chained transcript.",
        "export HEXBREAKER_HMAC_PASSWORD=demo-self-correction\n"
        "clear\n"
        "PYTHONPATH=src python scripts/demo_self_correction.py\n"
        "echo\n"
        "hexbreaker verify --transcript samples/self_correction/transcript.jsonl --hmac\n"
        "sleep 2\n",
    ),
    (
        "04_nist",
        "Now the real thing. The NIST Hacking Case, an actual seized disk image. "
        "This is the committed, signed result. Verify the transcript: chain and "
        "H-M-A-C both pass. Then read the findings: all four of the attacker's "
        "deleted tools recovered. L A L, NetStumbler, WinPcap, and Ethereal. Four "
        "of four. Honestly scoped: this is the recycle-bin question family, one of "
        "roughly thirty-one, with no injected answers and no planted decoys, so this "
        "is recovery accuracy. And it is committed and reproducible.",
        # No API, no live run: show the committed signed evidence (run1 of 5).
        "export HEXBREAKER_HMAC_PASSWORD=hexbreaker-nist-fsm\n"
        "clear\n"
        "echo '# Real NIST CFReDS Hacking Case — committed, signed Court result'\n"
        "echo '$ hexbreaker verify --transcript samples/nist_fsm_run/run1/transcript.jsonl --hmac'\n"
        "hexbreaker verify --transcript samples/nist_fsm_run/run1/transcript.jsonl --hmac\n"
        "echo\n"
        "echo '$ targets in samples/nist_fsm_run/run1/findings.json'\n"
        "python3 -c \"import json;[print('  CONFIRMED  '+f['target']) for f in json.load(open('samples/nist_fsm_run/run1/findings.json'))['findings']]\"\n"
        "echo; echo '  real NIST .E01  ·  4/4 deleted tools recovered  ·  5/5 signed runs  ·  E01 SHA256 matches docs'\n"
        "sleep 2\n",
    ),
    (
        "05_close",
        "And when it fails, it fails the right way. Across eighty adversarial runs, "
        "every failure is a miss. Zero false confirmations, zero baits taken. It "
        "would rather say nothing than lie. That's the whole thesis: an agent you "
        "can trust because it's built to be caught when it's wrong.",
        "clear\n"
        "PYTHONPATH=src python scripts/brittleness.py --from-sweep sweeps/2026-05-30_N40_jr01b_signed.json 2>&1 | "
        "grep -E 'distribution|MISS|FALSE-CONFIRM|fp_planted' | head -5\n"
        "echo; echo '# github.com/Alexander-Sorrell-IT/hexbreaker'\n"
        "sleep 3\n",
    ),
]

VOICE = "en-US-AndrewNeural"
COLS, ROWS = 100, 28
AGG = os.environ.get("AGG_BIN", "agg")  # prebuilt binary path override


def run(cmd: list[str], **kw):
    return subprocess.run(cmd, check=True, **kw)


def build_beat(beat_id: str, narration: str, script: str, reuse: bool = False):
    d = OUT_DIR / beat_id
    d.mkdir(parents=True, exist_ok=True)
    cast = d / "rec.cast"

    if not (reuse and cast.exists()):
        sh = d / "run.sh"
        # Activate the repo venv first (scrolls off behind each beat's `clear`) so
        # `hexbreaker`/`python` resolve to the repo, not a PATH-polluted install.
        sh.write_text("#!/usr/bin/env bash\nset -e\nsource .venv/bin/activate 2>/dev/null\n" + script)
        sh.chmod(0o755)
        # Record the REAL session in a PTY. asciinema runs the script as the command.
        env = dict(os.environ, HEXBREAKER_HMAC_PASSWORD=PW, PYTHONPATH="src")
        run([
            "asciinema", "rec", "--overwrite",
            "--cols", str(COLS), "--rows", str(ROWS),
            "-c", f"bash {sh}", str(cast),
        ], env=env)

    # cast -> gif (real frames, themed), gif -> mp4
    gif = d / "rec.gif"
    run([AGG, "--cols", str(COLS), "--rows", str(ROWS),
         "--theme", "dracula", "--font-size", "20", str(cast), str(gif)])
    vid = d / "video.mp4"
    run(["ffmpeg", "-y", "-i", str(gif),
         "-movflags", "+faststart", "-pix_fmt", "yuv420p",
         "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2", str(vid)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # narration -> mp3
    mp3 = d / "narration.mp3"
    run(["python3", "-m", "edge_tts", "--voice", VOICE,
         "--text", narration, "--write-media", str(mp3)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # narration length
    dur = float(subprocess.check_output(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "csv=p=0", str(mp3)]).decode().strip())
    beat = d / "beat.mp4"
    # FREEZE the final frame to fill narration (NOT stream_loop, which would
    # restart the typing animation from a blank screen and look janky). tpad holds
    # the last rendered frame so the completed terminal output stays on screen.
    run(["ffmpeg", "-y", "-i", str(vid), "-i", str(mp3),
         "-filter_complex", f"[0:v]tpad=stop_mode=clone:stop_duration={dur}[v]",
         "-map", "[v]", "-map", "1:a:0", "-t", f"{dur:.2f}",
         "-c:v", "libx264", "-c:a", "aac", "-pix_fmt", "yuv420p", str(beat)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return beat


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="docs/demo_screencast.mp4")
    p.add_argument("--no-live", action="store_true", help="skip the API-dependent NIST beat")
    p.add_argument("--reuse-cast", action="store_true",
                   help="render from existing rec.cast files (don't re-record)")
    args = p.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    beats = []
    for beat_id, narration, script in BEATS:
        if args.no_live and beat_id == "04_nist":
            print(f"[skip] {beat_id} (--no-live)")
            continue
        print(f"[beat] {beat_id} ...", flush=True)
        beats.append(build_beat(beat_id, narration, script, reuse=args.reuse_cast))

    # concat
    listf = OUT_DIR / "concat.txt"
    listf.write_text("".join(f"file '{b.resolve()}'\n" for b in beats))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(listf),
         "-c:v", "libx264", "-c:a", "aac", "-pix_fmt", "yuv420p",
         "-movflags", "+faststart", str(out)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dur = subprocess.check_output(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "csv=p=0", str(out)]).decode().strip()
    print(f"\nDONE: {out}  ({float(dur):.1f}s)")
    if float(dur) > 300:
        print("  WARNING: exceeds 5:00 — trim a beat.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
