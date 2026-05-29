"""Multi-seed Court sweep for honest F1 numbers.

Usage:
    python scripts/sweep.py --seeds 10 --templates timestomp --modes normal,provocateur \
                            --out /tmp/sweep_results.json

Runs each (seed, template, mode) combo through Court, scores against the answer key,
emits per-run results and aggregate statistics. Concurrency = 1 by default to stay
under the DeepSeek rate limit (we can raise later if needed).
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

import orjson

import os

from hexbreaker import llm
from hexbreaker.court.hmac_chain import HMAC_ENV, verify_signature
from hexbreaker.forge import template_registry_persistence, template_timestomp
from hexbreaker.forge.case import load_case
from hexbreaker.runner.court_runner import run_court_on_case
from hexbreaker.scorer.exact_match import FindingClass, score
from hexbreaker.transcript import verify

TEMPLATES = {
    "timestomp": template_timestomp.generate,
    "registry_persistence": template_registry_persistence.generate,
}


def run_one(
    seed: int,
    template: str,
    provocateur: bool,
    work_dir: Path,
    client: llm.DeepSeekClient,
) -> dict:
    mode = "provocateur" if provocateur else "normal"
    case_dir = work_dir / f"{template}-{seed}-{mode}"
    if case_dir.exists():
        import shutil
        shutil.rmtree(case_dir)
    TEMPLATES[template](seed, case_dir, provocateur=provocateur)
    t0 = time.monotonic()
    try:
        result = run_court_on_case(case_dir, client=client)
        wall = time.monotonic() - t0
        ok, reason = verify(result.transcript_path)
        # run_court_on_case signs the transcript when HEXBREAKER_HMAC_PASSWORD is
        # set; record whether the HMAC signature validates so the sweep proves
        # tamper-evidence end-to-end, not just chain integrity.
        if os.environ.get(HMAC_ENV):
            sig_result = verify_signature(result.transcript_path)
            hmac_ok = sig_result.ok
            hmac_reason = sig_result.reason
        else:
            hmac_ok = None
            hmac_reason = f"{HMAC_ENV} unset — run UNSIGNED"
        _, answer = load_case(case_dir)
        report = score(result.findings, answer)
        return {
            "seed": seed,
            "template": template,
            "mode": mode,
            "ok": True,
            "wall_s": round(wall, 2),
            "chain_ok": ok,
            "chain_reason": reason,
            "hmac_ok": hmac_ok,
            "hmac_reason": hmac_reason,
            "tp": report.tp,
            "fp": report.fp,
            "fn": report.fn,
            "fp_planted": report.fp_planted,
            "precision": report.precision,
            "recall": report.recall,
            "f1": report.f1,
            "n_findings": len(result.findings),
        }
    except Exception as e:
        return {
            "seed": seed,
            "template": template,
            "mode": mode,
            "ok": False,
            "wall_s": round(time.monotonic() - t0, 2),
            "error": f"{type(e).__name__}: {e}",
        }


def aggregate(results: list[dict]) -> dict:
    by_mode: dict[str, list[dict]] = {}
    for r in results:
        if not r.get("ok"):
            continue
        by_mode.setdefault(r["mode"], []).append(r)

    summary: dict[str, dict] = {}
    for mode, rs in by_mode.items():
        f1s = [r["f1"] for r in rs]
        precs = [r["precision"] for r in rs]
        recs = [r["recall"] for r in rs]
        summary[mode] = {
            "n_runs": len(rs),
            "f1_mean": round(statistics.mean(f1s), 4),
            "f1_stdev": round(statistics.stdev(f1s), 4) if len(f1s) > 1 else 0.0,
            "f1_min": min(f1s),
            "f1_max": max(f1s),
            "precision_mean": round(statistics.mean(precs), 4),
            "recall_mean": round(statistics.mean(recs), 4),
            "total_fp_planted": sum(r["fp_planted"] for r in rs),
            "wall_s_total": round(sum(r["wall_s"] for r in rs), 1),
            "wall_s_per_run": round(statistics.mean([r["wall_s"] for r in rs]), 2),
        }
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--templates", default="timestomp")
    parser.add_argument("--modes", default="normal,provocateur")
    parser.add_argument("--start-seed", type=int, default=4000)
    parser.add_argument("--out", required=True)
    parser.add_argument("--work-dir", default="/tmp/hexbreaker-sweep")
    args = parser.parse_args(argv)

    llm.load_env(Path(__file__).resolve().parent.parent / ".env")
    client = llm.DeepSeekClient()
    work_dir = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    seeds = list(range(args.start_seed, args.start_seed + args.seeds))
    templates = args.templates.split(",")
    modes = [m == "provocateur" for m in args.modes.split(",")]

    results: list[dict] = []
    total = len(seeds) * len(templates) * len(modes)
    i = 0
    for template in templates:
        for provocateur in modes:
            mode = "provocateur" if provocateur else "normal"
            for seed in seeds:
                i += 1
                print(f"[{i}/{total}] {template} mode={mode} seed={seed}", flush=True)
                r = run_one(seed, template, provocateur, work_dir, client)
                results.append(r)
                if r["ok"]:
                    print(
                        f"  → f1={r['f1']} tp={r['tp']} fp={r['fp']} fn={r['fn']}"
                        f" fp_planted={r['fp_planted']} wall={r['wall_s']}s",
                        flush=True,
                    )
                else:
                    print(f"  → ERROR: {r['error']}", flush=True)

    summary = aggregate(results)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(
        orjson.dumps({"results": results, "summary": summary}, option=orjson.OPT_INDENT_2)
    )

    print("\n=== SUMMARY ===")
    for mode, s in summary.items():
        print(f"{mode:>12}: n={s['n_runs']} f1_mean={s['f1_mean']} ± {s['f1_stdev']}"
              f"  precision={s['precision_mean']} recall={s['recall_mean']}"
              f"  fp_planted_total={s['total_fp_planted']}"
              f"  wall={s['wall_s_per_run']}s/run")
    print(f"\nfull results: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
