"""Pacing-tuned voiceover generator — make TTS sound human by RHYTHM, not just timbre.

The robotic feel of TTS is mostly even pacing: a whole paragraph synthesized at one
rate with no real pauses. This synthesizes PHRASE-BY-PHRASE and inserts human pauses
between them (short within a sentence, longer between beats), then measures the result
against human ranges and auto-nudges the pacing to land in band. Reusable across projects.

Backends (both free, local):
  - kokoro : fast onnx neural voices (bm_george, am_michael, af_heart, ...)
  - xtts   : Coqui XTTS-v2 voice CLONING from a reference clip (--speaker-wav)

Script format: a text file where blank lines separate BEATS; within a beat, sentences
(split on . ! ? : ;) get a short pause, beats get a long pause.

    python3 scripts/build_vo.py script.txt --backend kokoro --voice bm_george --out vo.wav --score
    python3 scripts/build_vo.py script.txt --backend xtts --speaker-wav ref.wav --out vo.wav --score
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import numpy as np
import soundfile as sf

SR = 24000  # both kokoro and xtts emit 24k
ROOT = Path("/media/phantomcore/AI_DRIVE/hackathons/evil")
SCORECARD = ROOT / "../Slack/grantscribe/demo/voice_scorecard.py"


def split_script(text: str) -> list[list[str]]:
    """-> list of beats; each beat is a list of phrase strings."""
    beats = []
    for para in re.split(r"\n\s*\n", text.strip()):
        para = " ".join(para.split())
        if not para:
            continue
        # split into sentence-ish phrases but keep the terminator
        phrases = re.split(r"(?<=[.!?:;])\s+", para)
        beats.append([p.strip() for p in phrases if p.strip()])
    return beats


def silence(seconds: float) -> np.ndarray:
    return np.zeros(int(SR * seconds), dtype=np.float32)


class Kokoro:
    def __init__(self, voice: str, speed: float):
        from kokoro_onnx import Kokoro as K
        self.k = K(str(ROOT / "tts_models/kokoro-v1.0.onnx"),
                   str(ROOT / "tts_models/voices-v1.0.bin"))
        self.voice, self.speed = voice, speed

    def say(self, text: str) -> np.ndarray:
        s, sr = self.k.create(text, voice=self.voice, speed=self.speed, lang="en-us")
        assert sr == SR, f"kokoro sr={sr}"
        return s.astype(np.float32)


class Xtts:
    def __init__(self, speaker_wav: str, speed: float):
        import os
        os.environ["COQUI_TOS_AGREED"] = "1"
        from TTS.api import TTS
        self.tts = TTS("tts_models/multilingual/multi-dataset/xtts_v2")
        self.speaker_wav, self.speed = speaker_wav, speed
        self._tmp = ROOT / "tts_samples/_xtts_phrase.wav"

    def say(self, text: str) -> np.ndarray:
        self.tts.tts_to_file(text=text, speaker_wav=self.speaker_wav, language="en",
                             speed=self.speed, file_path=str(self._tmp))
        s, sr = sf.read(self._tmp)
        if sr != SR:
            import math
            s = np.interp(np.linspace(0, len(s), int(len(s) * SR / sr)),
                          np.arange(len(s)), s)
        return s.astype(np.float32)


def assemble(beats, engine, intra: float, inter: float, lead: float = 0.3) -> np.ndarray:
    out = [silence(lead)]
    for bi, phrases in enumerate(beats):
        for pi, ph in enumerate(phrases):
            out.append(engine.say(ph))
            out.append(silence(intra if pi < len(phrases) - 1 else 0.0))
        out.append(silence(inter if bi < len(beats) - 1 else lead))
    return np.concatenate(out)


def measure(wav: np.ndarray, n_words: int) -> tuple[float, float]:
    """quick wpm + silence-fraction for the auto-tune loop."""
    dur = len(wav) / SR
    wpm = n_words / (dur / 60)
    # silence = frames below -35 dB of peak
    win = int(SR * 0.02)
    frames = wav[: len(wav) // win * win].reshape(-1, win)
    rms = np.sqrt((frames ** 2).mean(axis=1) + 1e-9)
    peak = rms.max()
    sil = float(np.mean(rms < peak * 10 ** (-35 / 20)))
    return wpm, sil


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("script")
    ap.add_argument("--backend", choices=["kokoro", "xtts"], default="kokoro")
    ap.add_argument("--voice", default="bm_george")          # kokoro
    ap.add_argument("--speaker-wav", default="")             # xtts
    ap.add_argument("--out", default="tts_samples/vo.wav")
    ap.add_argument("--speed", type=float, default=0.92)
    ap.add_argument("--intra", type=float, default=0.34)     # pause within a beat
    ap.add_argument("--inter", type=float, default=1.0)      # pause between beats
    ap.add_argument("--target-wpm", type=float, default=125)
    ap.add_argument("--autotune", action="store_true")
    ap.add_argument("--score", action="store_true")
    args = ap.parse_args()

    text = Path(args.script).read_text()
    beats = split_script(text)
    n_words = len(text.split())
    print(f"beats={len(beats)} phrases={sum(len(b) for b in beats)} words={n_words}")

    engine = (Kokoro(args.voice, args.speed) if args.backend == "kokoro"
              else Xtts(args.speaker_wav, args.speed))

    intra, inter = args.intra, args.inter
    for it in range(4 if args.autotune else 1):
        wav = assemble(beats, engine, intra, inter)
        wpm, sil = measure(wav, n_words)
        print(f"  iter {it}: intra={intra:.2f} inter={inter:.2f} -> {wpm:.0f} wpm, silence {sil*100:.0f}%")
        if not args.autotune or abs(wpm - args.target_wpm) <= 6:
            break
        # too fast -> lengthen beat pauses; too slow -> shorten
        inter = max(0.4, min(2.0, inter + (0.18 if wpm > args.target_wpm else -0.18)))
        intra = max(0.18, min(0.7, intra + (0.05 if wpm > args.target_wpm else -0.05)))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    # gentle peak normalize
    wav = wav / (np.abs(wav).max() + 1e-9) * 0.95
    sf.write(out, wav, SR)
    print(f"WROTE {out}  ({len(wav)/SR:.1f}s)")

    if args.score and SCORECARD.exists():
        txt = out.with_suffix(".txt")
        txt.write_text(" ".join(text.split()))
        subprocess.run([sys.executable, str(SCORECARD), str(out), str(txt)])


if __name__ == "__main__":
    main()
