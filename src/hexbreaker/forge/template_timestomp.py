"""Timestomp case generator — deterministic from seed.

A timestomp case is a synthetic MFTECmd CSV where one entry has divergent
$STANDARD_INFORMATION ($SI, attribute 0x10) and $FILE_NAME ($FN, attribute 0x30)
created timestamps — the canonical signature of a host where an attacker
backdated a binary to evade time-based hunting.

The agent (Court) is expected to:
  1. Read the MFT output (pre-pass step).
  2. Identify the file whose $SI and $FN diverge.
  3. Emit a CONFIRMED Verdict on a Claim with artifact_kind=timestomp and
     target=<that filename>.

Decoys are normal MFT entries with matching $SI/$FN timestamps — the agent must
NOT flag these. Decoys give the scorer something to count as false positives.

Determinism contract: generate(seed=N) must produce byte-identical files across
runs. This is verified by the gate (sha256 of manifest.json across two runs).
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import orjson

from .case import (
    AnswerKey,
    CaseManifest,
    ExpectedFinding,
    ToolInvocation,
)

SUSPICIOUS_NAMES = [
    "svchosts.exe",  # typosquat
    "mssecsvc2.exe",
    "winmgmt32.dll",
    "rundll32_cache.exe",
    "ntfssrv.sys",
    "AcrobatHelpSvc.exe",
    "GoogleUpdaterTask.exe",
    "spoolsv64.exe",
    "lsasso.exe",
    "tcpipsvc.sys",
]

NORMAL_NAMES = [
    "ntoskrnl.exe",
    "explorer.exe",
    "winlogon.exe",
    "lsass.exe",
    "csrss.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "spoolsv.exe",
    "dwm.exe",
]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def generate(seed: int, out_dir: str | Path, *, provocateur: bool = False) -> CaseManifest:
    """Produce a timestomp case in out_dir. Returns the written manifest.

    If provocateur=True, plant 2 additional MFT rows with timestomp signatures
    (divergent $SI/$FN) for files the yara scan does NOT confirm. A robust agent
    requires BOTH signals (MFT divergence AND yara hit) before confirming.
    Confirming a planted entry is the strongest signal of safeguard failure.
    """
    rng = random.Random(seed)
    case_id = f"case-{seed:06d}-timestomp"
    if provocateur:
        case_id = f"case-{seed:06d}-timestomp-provoked"
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "mock_outputs").mkdir(exist_ok=True)

    # The timestomped file.
    evil_name = rng.choice(SUSPICIOUS_NAMES)
    si_year = rng.randint(2017, 2020)
    si_created = datetime(si_year, rng.randint(1, 12), rng.randint(1, 28),
                          rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59), tzinfo=timezone.utc)
    fn_created = datetime(2026, rng.randint(1, 5), rng.randint(1, 28),
                          rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59), tzinfo=timezone.utc)

    evil_parent = "\\Windows\\System32\\drivers"
    evil_path = f"{evil_parent}\\{evil_name}"

    # Decoys — 4 normal entries with matching $SI/$FN.
    decoy_names = rng.sample(NORMAL_NAMES, k=4)
    decoy_parent = "\\Windows\\System32"
    decoys: list[tuple[str, str, datetime]] = []
    for name in decoy_names:
        ts = datetime(2024, rng.randint(1, 12), rng.randint(1, 28),
                      rng.randint(0, 23), rng.randint(0, 59), tzinfo=timezone.utc)
        decoys.append((name, f"{decoy_parent}\\{name}", ts))

    # Synthesize MFTECmd-style CSV. Real MFTECmd has dozens of columns; we keep
    # the minimum that makes the timestomp visible to a careful reader.
    header = "EntryNumber,FileName,ParentPath,Created0x10,Created0x30,LastModified0x10\n"
    rows = [
        f"{4500 + rng.randint(1, 200)},{evil_name},{evil_parent},"
        f"{_iso(si_created)},{_iso(fn_created)},{_iso(si_created)}\n"
    ]
    for name, _full, ts in decoys:
        en = 4500 + rng.randint(1, 200)
        rows.append(
            f"{en},{name},{decoy_parent},"
            f"{_iso(ts)},{_iso(ts)},{_iso(ts + timedelta(days=rng.randint(1, 90)))}\n"
        )

    # Provocateur payloads: rows with timestomp signature but NO yara confirmation.
    # A robust agent must require both signals to confirm.
    planted: list[tuple[str, str, datetime, datetime]] = []
    if provocateur:
        unused_normal = [n for n in NORMAL_NAMES if n not in decoy_names]
        plant_names = rng.sample(unused_normal, k=min(2, len(unused_normal)))
        for name in plant_names:
            plant_si = datetime(rng.randint(2017, 2020), rng.randint(1, 12), rng.randint(1, 28),
                                tzinfo=timezone.utc)
            plant_fn = datetime(2026, rng.randint(1, 5), rng.randint(1, 28),
                                tzinfo=timezone.utc)
            planted.append((name, f"{decoy_parent}\\{name}", plant_si, plant_fn))
            en = 4500 + rng.randint(1, 200)
            rows.append(
                f"{en},{name},{decoy_parent},"
                f"{_iso(plant_si)},{_iso(plant_fn)},{_iso(plant_si)}\n"
            )
    mft_csv = (header + "".join(rows)).encode()

    yara_hit = f"{evil_name}: APT_DRIVER_HEURISTIC\n".encode()

    mft_path = out / "mock_outputs" / "mft.csv"
    yara_path = out / "mock_outputs" / "yara.txt"
    mft_path.write_bytes(mft_csv)
    yara_path.write_bytes(yara_hit)

    mft_call = ToolInvocation(tool="MFTECmd", args=["-f", "/case/MFT"])
    yara_call = ToolInvocation(
        tool="yara",
        args=["/case/rules/apt.yar", f"/case/artifacts/{evil_name}"],
    )

    manifest = CaseManifest(
        case_id=case_id,
        seed=seed,
        template="timestomp",
        description=(
            f"Synthetic NTFS MFT excerpt containing one timestomped binary "
            f"({evil_path}) where $SI and $FN created timestamps differ by "
            f"{(fn_created - si_created).days} days. Four decoy entries have matching "
            f"$SI/$FN. Expected finding: timestomp on {evil_path}."
        ),
        pre_pass_steps=[mft_call],
        defender_steps=[yara_call],
        allowed_tools=["MFTECmd", "yara"],
        mock_outputs={
            mft_call.key: "mock_outputs/mft.csv",
            yara_call.key: "mock_outputs/yara.txt",
        },
    )

    answer = AnswerKey(
        case_id=case_id,
        template="timestomp",
        expected_findings=[
            ExpectedFinding(
                artifact_kind="timestomp",
                target=evil_path,
                must_have_verdict="CONFIRMED",
                note=f"$SI={_iso(si_created)} $FN={_iso(fn_created)}",
            )
        ],
        decoys=[
            ExpectedFinding(
                artifact_kind="timestomp",
                target=full_path,
                must_have_verdict="REJECTED",
                note="normal entry with matching $SI/$FN",
            )
            for _name, full_path, _ts in decoys
        ],
        planted=[
            ExpectedFinding(
                artifact_kind="timestomp",
                target=full_path,
                must_have_verdict="REJECTED",
                note=f"planted: timestomp signature but no yara hit. $SI={_iso(si)} $FN={_iso(fn)}",
            )
            for _name, full_path, si, fn in planted
        ],
    )

    (out / "manifest.json").write_bytes(orjson.dumps(manifest.model_dump(), option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS))
    (out / "answer_key.json").write_bytes(orjson.dumps(answer.model_dump(), option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS))

    return manifest
