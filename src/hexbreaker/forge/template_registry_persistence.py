"""Registry persistence case generator — deterministic from seed.

A registry-persistence case is a synthetic RECmd CSV showing
HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run with an evil binary
plus legit decoy entries. Persistence via Run keys is one of the most common
attacker techniques (T1547.001 in MITRE ATT&CK).

The agent (Court) is expected to:
  1. Read the RECmd Run-key dump (pre-pass).
  2. Identify the Run value whose binary path is in a user-writable location AND
     does NOT match a known vendor's canonical install location — i.e. an
     impersonation (a "Microsoft"/"Google"/"Adobe"-flavored name running out of a
     vendor-LOOKALIKE %APPDATA% subfolder, e.g. ...\\Microsoft\\OneDriveUpdate\\
     instead of the real ...\\Microsoft\\OneDrive\\).
  3. Emit a CONFIRMED Verdict with artifact_kind="persistence" and
     target=<full HKLM path including value name>.

Cheat-resistance (Option 1, "reasoning-only"). Every surface signal that fires
on the answer must also fire on >=1 decoy, so no cheap shortcut isolates it:
  * User-writable path: legit modern apps (OneDrive, Spotify, Teams, ...) ALSO
    live under %LOCALAPPDATA%/%APPDATA%, so "pick the user-writable one" collides
    with several benign decoys. Crucially the malicious entry sits under \\AppData\\
    too (in a vendor-LOOKALIKE subfolder), so no single path token — not "AppData",
    not "Temp"/"Public" — isolates it: the ONLY discriminator is the exact
    canonical subpath (KNOWN_VENDOR_PATHS), i.e. real domain knowledge.
  * Recency: ALL LastWriteTimestamps are drawn iid from one shared window, so the
    evil entry is the newest only with probability 1/N — "pick newest" does not
    isolate it.
  * Sysmon corroboration: the Sysmon RegistryEvent file names the evil key AND
    >=1 benign decoy key (and the benign rows also point at user-writable Images),
    so "echo the only Sysmon hit" / "the Sysmon row with a user-writable path"
    no longer extracts the answer.
  * ValueName: evil names are plausible vendor/system impersonations, not
    obvious-malware strings — the tell is the path, not the name.

Provocateur mode plants extra entries that LOOK persistence-like (user-writable,
impersonation-flavored) but have NO corroborating Sysmon RegistryEvent; the
defender must NOT flag them.
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

# Malicious Run entries. Each is a plausible vendor/system impersonation whose
# binary sits in a user-writable location that is NOT the canonical install path
# for the vendor it imitates (ProgramData\ root, Windows\Temp, Users\Public, or a
# generic AppData subdir that the real vendor does not use). EVERY evil sits
# under the user's %APPDATA%/%LOCALAPPDATA% — the SAME top-level location as the
# legit modern apps below — in a vendor-LOOKALIKE subfolder that is NOT the
# vendor's canonical install path (e.g. ...\AppData\Local\Microsoft\OneDriveUpdate\
# next to the real ...\AppData\Local\Microsoft\OneDrive\). This keeps the
# AppData token shared, so no single path token isolates the evil entry: the ONLY
# discriminator is the exact canonical subpath, which is the allowlist domain
# knowledge the ORACLE encodes and the CHEATER lacks. The tell is the path, not
# the name.
EVIL_BINARIES = [
    ("OneDriveUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\Microsoft\\OneDriveUpdate\\OneDriveUpdate.exe"),
    ("MicrosoftEdgeHealth", "C:\\Users\\Mr.Evil\\AppData\\Local\\Microsoft\\EdgeHealth\\msedge_health.exe"),
    ("GoogleUpdaterTask", "C:\\Users\\Mr.Evil\\AppData\\Local\\Google\\Updater\\GoogleUpdaterTask.exe"),
    ("AdobeARMHelper", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\Adobe\\ARMHelper\\AdobeARMHelper.exe"),
    ("WindowsSecurityHealth", "C:\\Users\\Mr.Evil\\AppData\\Local\\WindowsSecurity\\WindowsSecurityHealth.exe"),
    ("SpotifyWebHelper", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\SpotifyHelper\\SpotifyWebHelper.exe"),
    ("DiscordUpdater", "C:\\Users\\Mr.Evil\\AppData\\Local\\DiscordUpdate\\DiscordUpdater.exe"),
    ("TeamsMachineUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\Microsoft\\TeamsUpdate\\teams_machine_update.exe"),
]

# Legit Run entries that live in user-writable per-user app dirs — these are the
# NEAR-MISS decoys. Each is a real product in its REAL canonical install location
# (verifiable against KNOWN_VENDOR_PATHS below). "Is it user-writable?" is True
# for all of them, so that surface feature cannot isolate the malicious entry.
# Bare .exe paths (no command-line args) so the decoys are structurally identical
# in shape to the evil entries — an arg token that appears only on a decoy would
# otherwise let a cheater exclude that decoy and lift the answer's relative rank.
#
# Every legit user-writable decoy carries a product+modifier ValueName (Updater/
# Update/Helper/Task) — the SAME naming shape the evils are forced into (a Run
# value name is a unique key, so an impersonator cannot reuse a bare vendor name).
# Making the modifier-name shape UNIFORM across evil and the corroborated decoys
# means a name regex like /update|helper|task/ fires on every one of them and
# isolates none. These are REAL components in their REAL canonical dirs
# (OneDriveStandaloneUpdater, the Dropbox/Slack/Teams updaters, ...), so the path
# rule still rejects them — only the exact canonical subpath discriminates.
#
# CROSS-BUNDLE FREQUENCY DEFENCE. This pool is large (|MODIFIER_NAMED| == 24) and
# only n_modifier=3 are sampled per bundle, so each decoy ValueData recurs in
# 3/24 == 0.125 of bundles — IDENTICAL to the per-bundle recurrence of each evil
# name (1 of |EVIL_BINARIES| == 1/8 == 0.125). A blind attacker who builds a
# cross-bundle histogram of how often each user-writable ValueData / ValueName /
# parent-folder / exe-basename appears therefore sees evil and decoy in the SAME
# rarity band: neither "pick the corpus-rarest uw name" nor "pick the corpus-
# commonest" separates them. (The plant pool below matches the same 0.125 rate so
# provocateur mode does not re-open the separation.) Several entries carry
# lowercase/underscore exe basenames (steamwebhelper.exe, slack.exe, code.exe,
# ...) so the evils' lowercase/underscore basenames (msedge_health.exe,
# teams_machine_update.exe) do not stand out as a casing tell either.
MODIFIER_NAMED = [
    ("OneDriveStandaloneUpdater", "C:\\Users\\Mr.Evil\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe"),
    ("DropboxUpdate", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\Dropbox\\Update\\DropboxUpdate.exe"),
    ("SpotifyStartupHelper", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\Spotify\\SpotifyStartupHelper.exe"),
    ("DiscordUpdateHelper", "C:\\Users\\Mr.Evil\\AppData\\Local\\Discord\\app-1.0.9\\DiscordUpdateHelper.exe"),
    ("SlackUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\slack\\SlackUpdate.exe"),
    ("TeamsUpdateTask", "C:\\Users\\Mr.Evil\\AppData\\Local\\Microsoft\\Teams\\TeamsUpdateTask.exe"),
    ("ZoomLauncher", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe"),
    ("SteamWebHelperTask", "C:\\Users\\Mr.Evil\\AppData\\Local\\Steam\\steamwebhelper.exe"),
    ("VSCodeUpdater", "C:\\Users\\Mr.Evil\\AppData\\Local\\Programs\\Microsoft VS Code\\code.exe"),
    ("NotionUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\Programs\\Notion\\Notion.exe"),
    ("FigmaAgentUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\Figma\\FigmaAgent.exe"),
    ("OnePasswordUpdater", "C:\\Users\\Mr.Evil\\AppData\\Local\\1Password\\app\\8\\1Password.exe"),
    ("WhatsAppUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\WhatsApp\\WhatsApp.exe"),
    ("TelegramUpdater", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe"),
    ("GitHubDesktopUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\GitHubDesktop\\GitHubDesktop.exe"),
    ("ZoomMachineUpdate", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\Zoom\\bin\\zoom_update.exe"),
    ("WebexHelper", "C:\\Users\\Mr.Evil\\AppData\\Local\\CiscoSparkLauncher\\CiscoCollabHost.exe"),
    ("SignalUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\Programs\\signal-desktop\\Signal.exe"),
    ("BraveBrowserUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
    ("DropboxStartupHelper", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\Dropbox\\bin\\dropbox_update.exe"),
    ("SlackMachineUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\slack\\slack.exe"),
    ("PostmanAgentUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\Postman\\Postman.exe"),
    ("ObsidianUpdater", "C:\\Users\\Mr.Evil\\AppData\\Local\\Obsidian\\Obsidian.exe"),
    ("YammerSyncHelper", "C:\\Users\\Mr.Evil\\AppData\\Local\\Microsoft\\OneDrive\\FileCoAuth.exe"),
]

# Legit Run entries in protected (non-user-writable) install locations. These are
# the "obviously clean" decoys — they round out the dump so it looks like a real
# host, but they are not near-misses on the user-writable feature.
LEGIT_SYSTEM = [
    ("Adobe Updater", "C:\\Program Files (x86)\\Common Files\\Adobe\\OOBE\\PDApp\\UWA\\UpdaterStartupUtility.exe"),
    ("MicrosoftEdgeAutoLaunch", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"),
    ("SecurityHealth", "C:\\Windows\\System32\\SecurityHealthSystray.exe"),
    ("RTKBTFilterAudio", "C:\\Program Files\\Realtek\\Audio\\HDA\\RtkNGUI64.exe"),
    ("NvBackend", "C:\\Program Files (x86)\\NVIDIA Corporation\\Update Core\\NvBackend.exe"),
    ("VBoxTray", "C:\\Windows\\System32\\VBoxTray.exe"),
]

# Provocateur PLANT pool — impersonation-flavored Run entries in user-writable,
# NON-canonical locations that LOOK persistence-like by the path rule but carry NO
# corroborating Sysmon RegistryEvent (the defender must require both signals). This
# is a DEDICATED pool, disjoint in both ValueName and parent-folder token from
# EVIL_BINARIES and MODIFIER_NAMED. Plants are sampled n_plant=2 of |PLANT_BINARIES|
# == 16 per provocateur bundle, so each plant ValueData recurs in 2/16 == 0.125 of
# bundles — the SAME band as evil and decoy. (Previously plants were drawn from
# EVIL_BINARIES, which inflated each evil name's per-bundle presence to ~3/8 and
# re-opened the cross-bundle frequency separation in the "pick the commonest uw
# name" direction; a disjoint, rate-matched plant pool closes that.)
PLANT_BINARIES = [
    ("OutlookSyncAgent", "C:\\Users\\Mr.Evil\\AppData\\Local\\OfficeSync\\OutlookSyncAgent.exe"),
    ("ChromeHelperUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\ChromeUpdate\\ChromeHelperUpdate.exe"),
    ("AcrobatRdrUpdater", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\AcrobatHelper\\AcrobatRdrUpdater.exe"),
    ("DefenderScanHost", "C:\\Users\\Mr.Evil\\AppData\\Local\\DefenderHost\\DefenderScanHost.exe"),
    ("IntelGraphicsUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\IntelGfx\\IntelGraphicsUpdate.exe"),
    ("NvidiaWebHelper", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\NvWeb\\NvidiaWebHelper.exe"),
    ("RealtekAudioTask", "C:\\Users\\Mr.Evil\\AppData\\Local\\RtkAudioSvc\\RealtekAudioTask.exe"),
    ("JavaUpdateScheduler", "C:\\Users\\Mr.Evil\\AppData\\Local\\JreUpdate\\JavaUpdateScheduler.exe"),
    ("CortanaSearchHost", "C:\\Users\\Mr.Evil\\AppData\\Local\\SearchHost\\CortanaSearchHost.exe"),
    ("OfficeClickToRun", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\C2RHelper\\OfficeClickToRun.exe"),
    ("SkypeBackgroundHost", "C:\\Users\\Mr.Evil\\AppData\\Local\\SkypeHost\\SkypeBackgroundHost.exe"),
    ("WindowsUpdateAssist", "C:\\Users\\Mr.Evil\\AppData\\Local\\WuAssist\\WindowsUpdateAssist.exe"),
    ("AmdRadeonSettings", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\RadeonHelper\\AmdRadeonSettings.exe"),
    ("LogitechOptionsUpdate", "C:\\Users\\Mr.Evil\\AppData\\Local\\LogiUpdate\\LogitechOptionsUpdate.exe"),
    ("BitLockerSyncHelper", "C:\\Users\\Mr.Evil\\AppData\\Local\\BdeHelper\\BitLockerSyncHelper.exe"),
    ("PrintSpoolerHost", "C:\\Users\\Mr.Evil\\AppData\\Roaming\\SpoolHost\\PrintSpoolerHost.exe"),
]

# The intended forensic discriminator's allowlist: for a binary in a user-writable
# location, these are the ONLY canonical per-user install subpaths that are benign.
# A user-writable Run target is malicious iff none of these case-insensitive
# substrings appears in its ValueData. The legit user-writable decoys above each
# match exactly one; the evil entries match none — they sit in a vendor-LOOKALIKE
# AppData subfolder (e.g. ...\Microsoft\OneDriveUpdate\ vs the real ...\OneDrive\)
# whose exact canonical subpath is absent. Because every evil and every near-miss
# decoy is under \AppData\, no single path token isolates the answer — only this
# exact-subpath allowlist does. It is the domain knowledge the ORACLE encodes and
# the CHEATER lacks.
KNOWN_VENDOR_PATHS = (
    "\\AppData\\Local\\Microsoft\\OneDrive\\",
    "\\AppData\\Roaming\\Spotify\\",
    "\\AppData\\Local\\Microsoft\\Teams\\",
    "\\AppData\\Local\\Discord\\",
    "\\AppData\\Local\\slack\\",
    "\\AppData\\Roaming\\Dropbox\\",
    "\\AppData\\Roaming\\Zoom\\",
    "\\AppData\\Local\\Steam\\",
    "\\AppData\\Local\\Programs\\Microsoft VS Code\\",
    "\\AppData\\Local\\Programs\\Notion\\",
    "\\AppData\\Local\\Figma\\",
    "\\AppData\\Local\\1Password\\",
    "\\AppData\\Local\\WhatsApp\\",
    "\\AppData\\Roaming\\Telegram Desktop\\",
    "\\AppData\\Local\\GitHubDesktop\\",
    "\\AppData\\Local\\CiscoSparkLauncher\\",
    "\\AppData\\Local\\Programs\\signal-desktop\\",
    "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\",
    "\\AppData\\Local\\Postman\\",
    "\\AppData\\Local\\Obsidian\\",
)

# Markers for "user-writable" install location (case-insensitive substring match).
# The current case data places every candidate under \AppData\ (so the AppData
# token cannot isolate the answer); the other markers keep is_user_writable() a
# correct general forensic predicate (Public/ProgramData/Temp are also writable
# without admin) should the binary tables grow to use them.
USER_WRITABLE_MARKERS = (
    "\\appdata\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\windows\\temp\\",
)

RUN_KEY_PATH = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

# Shared timestamp window — ALL entries draw their LastWriteTimestamp from this
# range so recency is not a confound with maliciousness.
_TS_START = datetime(2024, 1, 1, tzinfo=timezone.utc)
_TS_END = datetime(2026, 5, 28, tzinfo=timezone.utc)
_TS_SPAN_S = int((_TS_END - _TS_START).total_seconds())


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _rand_ts(rng: random.Random) -> datetime:
    """A timestamp drawn iid from the shared [_TS_START, _TS_END] window."""
    return _TS_START + timedelta(seconds=rng.randint(0, _TS_SPAN_S))


def is_user_writable(value_data: str) -> bool:
    """True iff the binary path sits in a user-writable location."""
    low = value_data.lower()
    return any(m in low for m in USER_WRITABLE_MARKERS)


def is_canonical_vendor_path(value_data: str) -> bool:
    """True iff the path matches a known vendor's canonical per-user install dir."""
    low = value_data.lower()
    return any(p.lower() in low for p in KNOWN_VENDOR_PATHS)


def is_malicious_run_entry(value_data: str) -> bool:
    """The intended forensic rule: user-writable AND not a canonical vendor path."""
    return is_user_writable(value_data) and not is_canonical_vendor_path(value_data)


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
    evil_last_write = _rand_ts(rng)

    # Decoys: near-miss (user-writable, but in the vendor's CANONICAL dir) plus one
    # protected-location legit entry. The pool is deliberately dominated by
    # user-writable legit apps so "pick the user-writable entry" collides with many
    # benign decoys — the user-writable feature narrows the field but never isolates
    # the answer (1/N_userwritable, not 1/1). Structural, not probabilistic.
    #
    # Every user-writable decoy is MODIFIER-NAMED (see MODIFIER_NAMED), so the name
    # shape is UNIFORM across all corroborated user-writable entries — evil and
    # decoys alike — and a name regex (/update|helper|task/) isolates none.
    n_modifier = 3
    n_sys_decoys = 1
    uw_decoy_entries = rng.sample(MODIFIER_NAMED, k=n_modifier)
    sys_decoy_entries = rng.sample(LEGIT_SYSTEM, k=n_sys_decoys)
    decoy_entries = uw_decoy_entries + sys_decoy_entries
    decoys: list[tuple[str, str, datetime]] = []
    for name, path in decoy_entries:
        decoys.append((name, path, _rand_ts(rng)))

    # Provocateur plants: impersonation-flavored entries in user-writable,
    # non-canonical locations that LOOK malicious by the path rule but have NO
    # corroborating Sysmon RegistryEvent. Defender must require both signals.
    # Drawn from the DEDICATED PLANT_BINARIES pool (disjoint from EVIL_BINARIES and
    # MODIFIER_NAMED, sampled at the same 0.125 per-bundle rate) so plants do not
    # inflate any evil name's cross-bundle frequency.
    n_plant = 2
    planted: list[tuple[str, str]] = []
    if provocateur:
        plant_choices = rng.sample(PLANT_BINARIES, k=n_plant)
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
        rows.append(f"{RUN_KEY_PATH},{name},REG_SZ,{path},{_iso(_rand_ts(rng))}\n")
    # Shuffle so position is not a confound.
    rng.shuffle(rows)
    recmd_csv = (header + "".join(rows)).encode()

    # Corroborator: Sysmon EventID-13 RegistryEvent (Value Set) rows whose
    # TargetObject is the full Run key. The evil key gets a corroborating event —
    # but so does EVERY benign user-writable decoy, and those benign rows also
    # point at user-writable Images. So Sysmon presence is UNIFORM across all
    # user-writable legit entries and the evil one: neither "echo the only Sysmon
    # hit" nor "the Sysmon row whose Image is user-writable" extracts the answer.
    # Distinguishing evil from a benign user-writable app still requires the
    # non-canonical-path rule applied to the RECmd primary. The benign rows' keys
    # are decoys (REJECTED), never the answer. (This also satisfies the registry-
    # cheat (E) invariant: the file names the true target contiguously alongside
    # >=1 same-kind decoy target.)
    #
    # Provocateur plants do NOT get a Sysmon row — they are the only user-writable
    # entries lacking corroboration. A cheater that picks "the user-writable entry
    # WITHOUT a Sysmon event" therefore lands on a planted decoy (wrong), and the
    # defender's second-signal requirement (path rule AND Sysmon) correctly rejects
    # them.
    benign_sysmon = [(n, p, t) for (n, p, t) in decoys if (n, p) in uw_decoy_entries]
    evtx_header = "EventId,EventType,UtcTime,Image,TargetObject,Details\n"
    evtx_lines = [
        f"13,SetValue,{_iso(evil_last_write)},{evil_path},{evil_target},"
        f"REG_SZ {evil_path}\n"
    ]
    for name, path, ts in benign_sysmon:
        evtx_lines.append(
            f"13,SetValue,{_iso(ts)},{path},{RUN_KEY_PATH}\\{name},REG_SZ {path}\n"
        )
    # Shuffle Sysmon rows so the evil row is not always first.
    rng.shuffle(evtx_lines)
    evtx_out = (evtx_header + "".join(evtx_lines)).encode()

    (out / "mock_outputs" / "recmd_run.csv").write_bytes(recmd_csv)
    (out / "mock_outputs" / "sysmon_registry.csv").write_bytes(evtx_out)

    recmd_call = ToolInvocation(
        tool="RECmd",
        args=["-f", "/case/hives/SOFTWARE", "--kn", "Microsoft\\Windows\\CurrentVersion\\Run"],
    )
    evtx_call = ToolInvocation(
        tool="EvtxECmd",
        args=["-f", "/case/Microsoft-Windows-Sysmon%4Operational.evtx", "--csv", "/case/out"],
    )

    manifest = CaseManifest(
        case_id=case_id,
        seed=seed,
        template="registry_persistence",
        description=(
            f"Synthetic Run-key dump showing {1 + len(decoys) + len(planted)} entries in "
            f"{RUN_KEY_PATH}. One is malicious persistence: its binary sits in a "
            f"user-writable location that is NOT the imitated vendor's canonical "
            f"install path. {len(decoys)} are legitimate (several are modern apps that "
            f"legitimately live under %APPDATA%/%LOCALAPPDATA%); "
            f"{len(planted)} provocateur plants look persistence-like but have no "
            f"corroborating Sysmon RegistryEvent."
        ),
        pre_pass_steps=[recmd_call],
        defender_steps=[evtx_call],
        allowed_tools=["RECmd", "EvtxECmd"],
        mock_outputs={
            recmd_call.key: "mock_outputs/recmd_run.csv",
            evtx_call.key: "mock_outputs/sysmon_registry.csv",
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
                note=f"Run key with binary in non-canonical user-writable path: {evil_path}",
            )
        ],
        decoys=[
            ExpectedFinding(
                artifact_kind="persistence",
                target=f"{RUN_KEY_PATH}\\{name}",
                must_have_verdict="REJECTED",
                note="legitimate Run entry (canonical install location)",
            )
            for name, _, _ in decoys
        ],
        planted=[
            ExpectedFinding(
                artifact_kind="persistence",
                target=f"{RUN_KEY_PATH}\\{name}",
                must_have_verdict="REJECTED",
                note=f"planted: user-writable non-canonical path {path} but NO corroborating Sysmon RegistryEvent",
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
