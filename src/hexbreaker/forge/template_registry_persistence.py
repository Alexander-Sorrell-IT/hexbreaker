"""Registry persistence case generator — deterministic from seed.

A registry-persistence case is a synthetic RECmd CSV showing
HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run with an evil binary
plus legit decoy entries. Persistence via Run keys is one of the most common
attacker techniques (T1547.001 in MITRE ATT&CK).

The agent (Court) is expected to:
  1. Read the RECmd Run-key dump (pre-pass).
  2. Identify the Run value whose binary path looks suspicious (LOLBin,
     typosquat, AppData, Temp, etc.).
  3. Emit a CONFIRMED Verdict with artifact_kind="persistence" and
     target=<full HKLM path including value name>.

Decoys are legitimate Run keys (Adobe updater, OneDrive, MSEdge updater).
Provocateur mode plants extra legit-named entries that the agent must NOT flag.
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

EVIL_BINARIES = [
    ("evil_persistence", "C:\\Users\\Public\\AppData\\malware.exe"),
    ("svchosts_loader", "C:\\ProgramData\\svchosts.exe"),
    ("WinUpdtHelper", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\winupdt.exe"),
    ("AcrobatAssistant", "C:\\Users\\Public\\AcrobatAssistant.exe"),
    ("MicrosoftTelemetry", "C:\\Windows\\Temp\\mstelemetry.exe"),
    ("ChromeUpdater_2", "C:\\Users\\Mr.Evil\\AppData\\Local\\Temp\\chromeupd.exe"),
    ("GoogleHelperSvc", "C:\\ProgramData\\Google\\GoogleHelperSvc.exe"),
    ("OneDriveHelper", "C:\\Users\\Public\\OneDriveHelper.exe"),
]

LEGIT_BINARIES = [
    ("Adobe Updater", "C:\\Program Files (x86)\\Common Files\\Adobe\\OOBE\\PDApp\\UWA\\UpdaterStartupUtility.exe"),
    ("OneDrive", "C:\\Users\\Mr.Evil\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background"),
    ("MicrosoftEdgeAutoLaunch", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe --no-startup-window"),
    ("SecurityHealth", "C:\\Windows\\System32\\SecurityHealthSystray.exe"),
    ("RTKBTFilterAudio", "C:\\Program Files\\Realtek\\Audio\\HDA\\RtkNGUI64.exe"),
    ("NvBackend", "C:\\Program Files (x86)\\NVIDIA Corporation\\Update Core\\NvBackend.exe"),
    ("VBoxTray", "C:\\Windows\\System32\\VBoxTray.exe"),
    ("Spotify Web Helper", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\Spotify\\SpotifyWebHelper.exe"),
]

RUN_KEY_PATH = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def generate(seed: int, out_dir: str | Path, *, provocateur: bool = False) -> CaseManifest:
    """Produce a registry-persistence case in out_dir."""
    rng = random.Random(seed)
    case_id = f"case-{seed:06d}-registry"
    if provocateur:
        case_id = f"case-{seed:06d}-registry-provoked"
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "mock_outputs").mkdir(exist_ok=True)

    # Pick the evil entry.
    evil_value, evil_path = rng.choice(EVIL_BINARIES)
    evil_target = f"{RUN_KEY_PATH}\\{evil_value}"
    evil_last_write = datetime(2026, rng.randint(1, 5), rng.randint(1, 28), rng.randint(0, 23), rng.randint(0, 59), tzinfo=timezone.utc)

    # Decoys: legit Run entries.
    n_decoys = 4
    decoy_entries = rng.sample(LEGIT_BINARIES, k=n_decoys)
    decoys: list[tuple[str, str, datetime]] = []
    for name, path in decoy_entries:
        ts = datetime(2024, rng.randint(1, 12), rng.randint(1, 28), tzinfo=timezone.utc)
        decoys.append((name, path, ts))

    # Provocateur plants: legit-named values pointing at user-writable locations
    # that LOOK persistence-like but have no yara confirmation. Defender must
    # require both signals.
    planted: list[tuple[str, str]] = []
    if provocateur:
        unused_evil = [(n, p) for n, p in EVIL_BINARIES if n != evil_value]
        plant_choices = rng.sample(unused_evil, k=min(2, len(unused_evil)))
        for name, path in plant_choices:
            planted.append((name, path))

    # Synthesize a RECmd-style Run-key dump. Real RECmd has more columns; we
    # keep the minimum that exposes the attack surface to a careful reader.
    header = "KeyPath,ValueName,ValueType,ValueData,LastWriteTimestamp\n"
    rows = [
        f"{RUN_KEY_PATH},{evil_value},REG_SZ,{evil_path},{_iso(evil_last_write)}\n"
    ]
    for name, path, ts in decoys:
        rows.append(f"{RUN_KEY_PATH},{name},REG_SZ,{path},{_iso(ts)}\n")
    for name, path in planted:
        plant_ts = datetime(2026, rng.randint(1, 5), rng.randint(1, 28), tzinfo=timezone.utc)
        rows.append(f"{RUN_KEY_PATH},{name},REG_SZ,{path},{_iso(plant_ts)}\n")
    # Shuffle so position is not a confound.
    rng.shuffle(rows)
    recmd_csv = (header + "".join(rows)).encode()

    # Yara hit on the evil binary only.
    yara_hit = f"{evil_path}: APT_PERSISTENCE_HEURISTIC\n".encode()

    (out / "mock_outputs" / "recmd_run.csv").write_bytes(recmd_csv)
    (out / "mock_outputs" / "yara.txt").write_bytes(yara_hit)

    recmd_call = ToolInvocation(
        tool="RECmd",
        args=["-f", "/case/hives/SOFTWARE", "--kn", "Microsoft\\Windows\\CurrentVersion\\Run"],
    )
    yara_call = ToolInvocation(
        tool="yara",
        args=["/case/rules/persistence.yar", evil_path],
    )

    manifest = CaseManifest(
        case_id=case_id,
        seed=seed,
        template="registry_persistence",
        description=(
            f"Synthetic Run-key dump showing {1 + n_decoys + len(planted)} entries in "
            f"{RUN_KEY_PATH}. One ({evil_value} -> {evil_path}) is malicious "
            f"persistence in a user-writable path; {n_decoys} are legitimate; "
            f"{len(planted)} provocateur plants point at user-writable locations "
            f"without yara confirmation. Expected finding: persistence on {evil_target}."
        ),
        pre_pass_steps=[recmd_call],
        defender_steps=[yara_call],
        allowed_tools=["RECmd", "yara"],
        mock_outputs={
            recmd_call.key: "mock_outputs/recmd_run.csv",
            yara_call.key: "mock_outputs/yara.txt",
        },
    )

    answer = AnswerKey(
        case_id=case_id,
        template="registry_persistence",
        expected_findings=[
            ExpectedFinding(
                artifact_kind="persistence",
                target=evil_target,
                must_have_verdict="CONFIRMED",
                note=f"Run key with binary in user-writable path: {evil_path}",
            )
        ],
        decoys=[
            ExpectedFinding(
                artifact_kind="persistence",
                target=f"{RUN_KEY_PATH}\\{name}",
                must_have_verdict="REJECTED",
                note="legitimate Run entry",
            )
            for name, _, _ in decoys
        ],
        planted=[
            ExpectedFinding(
                artifact_kind="persistence",
                target=f"{RUN_KEY_PATH}\\{name}",
                must_have_verdict="REJECTED",
                note=f"planted: Run entry pointing at user-writable path {path} but NO yara confirmation",
            )
            for name, path in planted
        ],
    )

    (out / "manifest.json").write_bytes(
        orjson.dumps(manifest.model_dump(), option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS)
    )
    (out / "answer_key.json").write_bytes(
        orjson.dumps(answer.model_dump(), option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS)
    )

    return manifest
