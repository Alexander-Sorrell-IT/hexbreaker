"""Prefetch execution case generator — deterministic from seed.

A Prefetch case is a synthetic PECmd CSV (the Windows Prefetch view) listing
executables the OS recorded as having RUN, each with its resolved FullPath, run
count, and last-run time. A `.pf` entry is strong execution evidence: the binary
at that path was launched on this host.

The agent (Court) is expected to:
  1. Read the PECmd dump (pre-pass step).
  2. Identify the entry whose FullPath is suspicious (user-writable / staging
     location: Temp, AppData, Public, ProgramData) AND which yara flags as a
     known-bad signature.
  3. Emit a CONFIRMED Verdict with artifact_kind="prefetch" and
     target=<that binary's FullPath>.

Honesty under JR-01 (CONFIRMED requires citations from >=2 distinct tool kinds):
the one true target has GENUINE per-target corroboration from a SECOND, distinct
tool whose stdout literally names that exact target.
  - PRIMARY: PECmd — the Prefetch entry's resolved FullPath IS the full
    contiguous executable path; this is the execution signal (the binary ran).
  - CORROBORATOR: yara — a content signature hit. yara honestly emits the path
    of the file whose CONTENT matched a rule, so it names the SAME FullPath.

Both legs name the SAME contiguous binary path. The honest reading is narrow:
Prefetch = the binary at this path executed; yara = the binary at this path
matches a malware signature. Together = a malicious binary executed from this
path. yara is NOT claimed to prove execution; PECmd is NOT claimed to prove
maliciousness.

Decoys are legitimate executables (Program Files / System32) with real Prefetch
entries that the agent must NOT flag — no yara hit. Provocateur mode plants ONE
entry that carries the suspicious-path + executed PRIMARY signal but has NO yara
corroboration: the bait a robust agent must REJECT.

Determinism contract: generate(seed=N) must produce byte-identical files across
runs.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone
from pathlib import Path

import orjson

from .case import (
    AnswerKey,
    CaseManifest,
    ExpectedFinding,
    ToolInvocation,
)

# Malicious binaries: suspicious, user-writable staging paths. The evil entry AND
# any provocateur plant are drawn from here — they share the same suspicious-path
# + executed PRIMARY signal, so the ONLY differentiator is the yara corroborator.
EVIL_BINARIES = [
    "C:\\Users\\Public\\malware.exe",
    "C:\\ProgramData\\svchosts.exe",
    "C:\\Users\\Mr.Evil\\AppData\\Roaming\\winupdt.exe",
    "C:\\Windows\\Temp\\mstelemetry.exe",
    "C:\\Users\\Mr.Evil\\AppData\\Local\\Temp\\chromeupd.exe",
    "C:\\ProgramData\\Google\\GoogleHelperSvc.exe",
    "C:\\Users\\Public\\AcrobatAssistant.exe",
    "C:\\Users\\Mr.Evil\\AppData\\Roaming\\rundll32_cache.exe",
]

# Legitimate binaries: trusted install locations. Decoys — they ran, but benign.
LEGIT_BINARIES = [
    "C:\\Windows\\System32\\notepad.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Windows\\System32\\SecurityHealthSystray.exe",
    "C:\\Program Files\\Realtek\\Audio\\HDA\\RtkNGUI64.exe",
    "C:\\Program Files (x86)\\NVIDIA Corporation\\Update Core\\NvBackend.exe",
    "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
    "C:\\Program Files\\7-Zip\\7zFM.exe",
]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def generate(seed: int, out_dir: str | Path, *, provocateur: bool = False) -> CaseManifest:
    """Produce a Prefetch execution case in out_dir. Returns the manifest.

    One true finding: a malicious binary the Prefetch shows executed from a
    user-writable path (PECmd primary), corroborated by a yara signature hit on
    the SAME FullPath. If provocateur=True, plant ONE additional Prefetch entry
    that carries the suspicious-path + executed primary signal but has NO yara hit
    — a robust agent must REJECT it.
    """
    rng = random.Random(seed)
    case_id = f"case-{seed:06d}-prefetch"
    if provocateur:
        case_id = f"case-{seed:06d}-prefetch-provoked"
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "mock_outputs").mkdir(exist_ok=True)

    # ----- Pick the evil binary (single source of truth for the target). -----
    evil_path = rng.choice(EVIL_BINARIES)
    evil_name = evil_path.rsplit("\\", 1)[1]
    evil_runs = rng.randint(1, 12)
    evil_last_run = datetime(2026, rng.randint(1, 5), rng.randint(1, 28),
                             rng.randint(0, 23), rng.randint(0, 59), tzinfo=timezone.utc)

    # ----- Decoys: legitimate executables in trusted locations. -----
    n_decoys = 4
    decoy_paths = rng.sample(LEGIT_BINARIES, k=n_decoys)
    decoys: list[tuple[str, int, datetime]] = []
    for path in decoy_paths:
        ts = datetime(2024, rng.randint(1, 12), rng.randint(1, 28),
                      rng.randint(0, 23), rng.randint(0, 59), tzinfo=timezone.utc)
        decoys.append((path, rng.randint(3, 200), ts))

    # ----- Provocateur plant: suspicious-path + executed primary, NO yara hit. -----
    planted_path: str | None = None
    if provocateur:
        unused_evil = [p for p in EVIL_BINARIES if p != evil_path]
        planted_path = rng.choice(unused_evil)

    # ----- Synthesize PECmd CSV (execution primary). -----
    # ExecutableName + the resolved FullPath (the contiguous path the answer key
    # targets) + run count + last run time.
    header = "ExecutableName,FullPath,RunCount,LastRun\n"
    rows = [
        f"{evil_name},{evil_path},{evil_runs},{_iso(evil_last_run)}\n"
    ]
    for path, runs, ts in decoys:
        name = path.rsplit("\\", 1)[1]
        rows.append(f"{name},{path},{runs},{_iso(ts)}\n")
    if planted_path is not None:
        plant_runs = rng.randint(1, 12)
        plant_ts = datetime(2026, rng.randint(1, 5), rng.randint(1, 28),
                            rng.randint(0, 23), rng.randint(0, 59), tzinfo=timezone.utc)
        plant_name = planted_path.rsplit("\\", 1)[1]
        rows.append(f"{plant_name},{planted_path},{plant_runs},{_iso(plant_ts)}\n")
    # Shuffle so the evil row is not always at index 0 — position must not be a
    # confound with the suspicious-path signal.
    rng.shuffle(rows)
    pecmd_csv = (header + "".join(rows)).encode()

    # ----- Synthesize yara output (corroborator). -----
    # ONLY the true evil binary is hit; decoys and any plant are NOT hit. One
    # honest line, no padding — a benign yara "hit" would falsely mark a decoy.
    yara_hit = f"APT_LOADER_HEURISTIC {evil_path}\n".encode()

    (out / "mock_outputs" / "prefetch.csv").write_bytes(pecmd_csv)
    (out / "mock_outputs" / "yara.txt").write_bytes(yara_hit)

    pecmd_call = ToolInvocation(
        tool="PECmd",
        args=["-d", "/case/C/Windows/Prefetch", "--csv", "/case/out"],
    )
    yara_call = ToolInvocation(
        tool="yara",
        args=["/case/rules/loader.yar", evil_path],
    )

    manifest = CaseManifest(
        case_id=case_id,
        seed=seed,
        template="prefetch",
        description=(
            f"Synthetic Prefetch dump listing {1 + n_decoys + (1 if planted_path else 0)} "
            f"executables recorded as run. One ({evil_path}, {evil_runs} runs) is "
            f"malware executed from a user-writable path (PECmd primary), "
            f"corroborated by a yara signature hit on the SAME path. {n_decoys} "
            f"decoys are legitimate executables in trusted locations. "
            + (
                f"Provocateur plant: {planted_path} carries the same suspicious-path "
                f"+ executed primary signal but has NO corroborating yara hit — must "
                f"NOT be confirmed."
                if planted_path
                else "No provocateur plants."
            )
            + f" Expected finding: prefetch on {evil_path}."
        ),
        pre_pass_steps=[pecmd_call],
        defender_steps=[yara_call],
        allowed_tools=["PECmd", "yara"],
        mock_outputs={
            pecmd_call.key: "mock_outputs/prefetch.csv",
            yara_call.key: "mock_outputs/yara.txt",
        },
    )

    answer = AnswerKey(
        case_id=case_id,
        template="prefetch",
        expected_findings=[
            ExpectedFinding(
                artifact_kind="prefetch",
                target=evil_path,
                must_have_verdict="CONFIRMED",
                note=(
                    "malware executed from a user-writable path (Prefetch); "
                    "corroborated by a yara signature hit on the same FullPath"
                ),
            )
        ],
        decoys=[
            ExpectedFinding(
                artifact_kind="prefetch",
                target=path,
                must_have_verdict="REJECTED",
                note="legitimate executable in a trusted install location; no yara hit",
            )
            for path, _runs, _ts in decoys
        ],
        planted=(
            [
                ExpectedFinding(
                    artifact_kind="prefetch",
                    target=planted_path,
                    must_have_verdict="REJECTED",
                    note=(
                        "planted: Prefetch entry executed from a user-writable path "
                        "(primary signal) but NO yara corroboration"
                    ),
                )
            ]
            if planted_path
            else []
        ),
    )

    (out / "manifest.json").write_bytes(
        orjson.dumps(manifest.model_dump(), option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS)
    )
    (out / "answer_key.json").write_bytes(
        orjson.dumps(answer.model_dump(), option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS)
    )

    return manifest
