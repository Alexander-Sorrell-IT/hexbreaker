r"""Prefetch execution case generator — deterministic from seed.

A Prefetch case is a synthetic PECmd CSV (the Windows Prefetch view) listing
executables the OS recorded as having RUN, each with its resolved FullPath, run
count, and last-run time. A `.pf` entry is strong execution evidence: the binary
at that path was launched on this host.

The agent (Court) is expected to:
  1. Read the PECmd dump (pre-pass step).
  2. Identify the entry that is MASQUERADING: a binary whose basename is a known
     Windows system process but whose Prefetch FullPath is NOT that process's
     canonical location — corroborated by a malware-family yara signature hit AND
     the absence of a valid Microsoft Authenticode signature (a real system binary
     would be catalog-signed). (T1036.005 — match legitimate name or location.)
  3. Emit a CONFIRMED Verdict with artifact_kind="prefetch" and
     target=<that binary's FullPath>.

REASONING-ONLY (cheat-resistance, Option 1): every SURFACE signal that fires on
the answer also fires on >=1 decoy, and the decoys carry benign near-miss tells,
so no cheap shortcut isolates the answer. The malicious row is the CONJUNCTION of
THREE meaning-level legs, each saturated by a benign decoy (the timestomp
precedent):
  (A) MASQUERADE — a system-process basename whose dir is NOT its canonical home.
  (B) MALWARE-family yara hit (a real content signature, not a benign PUA/packer).
  (C) UNSIGNED — absent from the Microsoft Authenticode/catalog scan.

THE PUBLIC-CONSTANT-MEMBERSHIP + LOCATION-REGEX DEFENCE (cheat-hunt, 2026-06-09).
A 30-agent adversarial hunt found a SEVERE structural leak: a submitter granted
the open-source MIT Forge can read the seed-invariant constant lists
(MASQUERADE_NAMES, MALWARE_YARA_RULES) and the catalog scan, and the answer was
the UNIQUE row satisfying basename∈system-name-list ∧ rule∈MALWARE_YARA_RULES ∧
unsigned — a PUBLIC-MEMBERSHIP conjunction that needs ZERO canonical-home
reasoning. A first repair that added unsigned malware-flagged decoys in scattered
canonical homes (System32, Program Files) STILL leaked, because the answer's
LOCATION was a user-writable staging dir and "user-writable staging ⟹
non-canonical" for a System32-only process — so the cheater's path-prefix regex
(`startswith staging`) reproduced leg A for free, and the cell
masqname∩malware∩unsigned∩staging was a singleton (any genuinely-unsigned staging
masquerade IS the answer, by definition). The same wall blocks every empty
"wrong" directory (Windows\Help, Windows\Fonts, ...): no LEGITIMATE system binary
lives there, so a masqname there is the only such row and any path regex isolates
it.

ROOT-CAUSE FIX (this file) — CO-LOCATION in a directory that legitimately houses
OTHER system binaries. The answer is a system-process basename dropped into a
HOME directory that is the canonical home of SEVERAL OTHER system processes but
NOT of the answer's own basename (a classic T1036.005: e.g. svchost.exe placed in
C:\Windows root next to the real explorer.exe/regedit.exe, or explorer.exe placed
in System32 next to the real svchost.exe/lsass.exe). In that SAME directory we
place >=5 BENIGN co-residents whose canonical home IS that directory, each a
heuristic MALWARE-family yara FALSE POSITIVE that is also UNSIGNED. So:
  - the answer N_a in dir D, with D NOT in canonical[N_a]  => the oracle PICKS it;
  - each co-resident N_b in D, with D IN canonical[N_b]    => the oracle REJECTS it;
  - answer and co-residents share the EXACT directory, so EVERY path-based cheater
    feature is identical between them — the staging regex, the not-Windows regex,
    the Windows-not-System32 regex, the exact-dir match, path depth, every path
    segment, AND the full public-label conjunction (system-name ∩ malware-rule ∩
    unsigned). The co-residents bracket the answer in basename AND full-path order.
The ONLY thing that separates the answer from a co-resident is the MEANING of the
per-name canonical install location — does THIS basename belong in THIS dir? That
is the canonical-location reasoning the ORACLE encodes (a name->home MAP) and the
membership/regex cheater lacks. A REASONING-ONLY discriminator therefore EXISTS:
the answer and each co-resident agree on every public label AND every path
feature; only the canonical-home map separates them. (The co-residents are
"unsigned" so they also saturate leg C — the answer's third, exculpatory leg; in
the real world a heuristic yara FP on a legit-but-not-catalog-signed system
component is exactly this near-miss.)

Every PAIRWISE intersection of the three legs (and of their surface proxies) ALSO
fires on a benign decoy, so no 2-feature membership shortcut isolates the answer
(see the retained near-miss decoys: a benign-rule yara hit on a correctly-located
binary, a second non-system malware sample, a SIGNED malware-flagged masquerade, a
benign-rule process-impersonation, a legit per-user app, a duplicated-basename
browser). A strategy that reconstructs all three legs HAS reimplemented the
forensic rule — but it MUST compute the per-name canonical home (domain
knowledge), not test public-list membership or run a path regex.

Honesty under JR-01 (CONFIRMED requires citations from >=2 distinct tool kinds):
the one true target has GENUINE per-target corroboration from a SECOND, distinct
tool whose stdout names that exact target.
  - PRIMARY: PECmd — the Prefetch entry's resolved FullPath IS the full
    contiguous executable path; this is the execution signal (the binary ran from
    a path inconsistent with its system-process name).
  - CORROBORATOR: yara — a malware-family content signature hit. yara names the
    matched file by its BASENAME (real yara prints the rule + the scanned
    filename), so the agent joins that basename to the PECmd FullPath column. The
    full target string never appears contiguously in the issued bundle (the
    registry cheat-resistance invariant; same column-split posture as timestomp).
  - SIGNATURE: a SECOND yara invocation against a known-good catalog ruleset
    (MS_CATALOG_SIGNED) lists the basenames of catalog-signed binaries; the answer
    is ABSENT (unsigned). This is the third, exculpatory leg the decoys exploit.

Decoys are legitimate executables the agent must NOT flag. Provocateur mode
plants ONE entry that ALSO masquerades (system-process basename in a wrong home,
the primary tell) but has NO malware-family yara corroboration: the bait a robust
agent must REJECT.

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

# ----- Canonical install homes. Each system-process basename maps to its TRUE
# directory. A `.pf` entry for one of these basenames running from a DIFFERENT
# directory is the masquerade (T1036.005). The CO-LOCATION defence requires that
# the answer's wrong dir is the canonical home of OTHER system names (so benign
# co-residents share the exact dir) — so we model THREE real multi-occupant homes.
WINROOT = "C:\\Windows"
SYSTEM32 = "C:\\Windows\\System32"
SYSWOW64 = "C:\\Windows\\SysWOW64"
DEFENDER_HOME = "C:\\Program Files\\Windows Defender"

# ----- THE SINGLE PUBLIC CONSTANT: one HETEROGENEOUS name->canonical-home(s) map.
# This is the only system-name list a submitter can read. It is deliberately NOT
# split into homogeneous per-home sublists (e.g. an all-System32 MASQUERADE_NAMES),
# because a homogeneous sublist leaks "home == System32" as a free KEY-membership
# test — the cheat-hunt's 0.500 leak. With ONE heterogeneous map, key-membership
# means only "is a system-process name" (saturated: every candidate row is one), and
# recovering a per-home partition FORCES reading the home VALUES — which is exactly
# `parent not in SYSTEM_PROCESS_HOMES[name]`, the ORACLE. (The registry precedent:
# reading KNOWN_VENDOR_PATHS values is oracle-class reasoning, not a surface cheat.)
# Every name is a genuine Windows system process in its real home:
#   System32: svchost..fontdrvhost; Windows root: explorer..notepad; both System32
#   and SysWOW64 (dual-home 32/64-bit): rundll32..mshta; Program Files Defender:
#   MsMpEng..MpDefenderCoreService.
SYSTEM_PROCESS_HOMES: dict[str, list[str]] = {
    # System32-home processes
    "svchost.exe": [SYSTEM32],
    "lsass.exe": [SYSTEM32],
    "services.exe": [SYSTEM32],
    "winlogon.exe": [SYSTEM32],
    "csrss.exe": [SYSTEM32],
    "spoolsv.exe": [SYSTEM32],
    "wininit.exe": [SYSTEM32],
    "smss.exe": [SYSTEM32],
    "taskhostw.exe": [SYSTEM32],
    "dllhost.exe": [SYSTEM32],
    "conhost.exe": [SYSTEM32],
    "sihost.exe": [SYSTEM32],
    "ctfmon.exe": [SYSTEM32],
    "fontdrvhost.exe": [SYSTEM32],
    # Windows-ROOT processes (all genuinely ship in C:\Windows)
    "explorer.exe": [WINROOT],
    "regedit.exe": [WINROOT],
    "write.exe": [WINROOT],
    "winhlp32.exe": [WINROOT],
    "HelpPane.exe": [WINROOT],
    "splwow64.exe": [WINROOT],
    "bfsvc.exe": [WINROOT],
    "hh.exe": [WINROOT],
    "notepad.exe": [WINROOT],
    # Dual-home (legit in BOTH System32 and SysWOW64 on x64)
    "rundll32.exe": [SYSTEM32, SYSWOW64],
    "regsvr32.exe": [SYSTEM32, SYSWOW64],
    "cmd.exe": [SYSTEM32, SYSWOW64],
    "wscript.exe": [SYSTEM32, SYSWOW64],
    "mshta.exe": [SYSTEM32, SYSWOW64],
    # Program Files\Windows Defender (genuine Defender executables)
    "MsMpEng.exe": [DEFENDER_HOME],
    "MpCmdRun.exe": [DEFENDER_HOME],
    "NisSrv.exe": [DEFENDER_HOME],
    "MpDefenderCoreService.exe": [DEFENDER_HOME],
}

# The ORACLE's canonical-home map IS the single public map above (no separate
# reconstruction — the test reads SYSTEM_PROCESS_HOMES directly).
_CANONICAL = SYSTEM_PROCESS_HOMES

# All public system-process basenames. Every candidate row in the dump carries one
# of these, so "is a system-process name" never narrows the field.
_ALL_SYSNAMES = set(SYSTEM_PROCESS_HOMES)

# ----- Internal generation helpers (NOT importable homogeneous "legs"; derived
# from the single public map by reading its home VALUES — i.e. these are oracle-
# class groupings used only to BUILD a realistic dump, never a cheater partition).
_DUAL_HOME_NAMES = [n for n, h in SYSTEM_PROCESS_HOMES.items() if h == [SYSTEM32, SYSWOW64]]
_DEFENDER_NAMES = [n for n, h in SYSTEM_PROCESS_HOMES.items() if h == [DEFENDER_HOME]]

# Multi-occupant co-location homes the ANSWER may hide in (each houses >=5 system
# names so we can place >=5 benign canonical co-residents alongside the answer).
# System32 (14 names) and the Windows root (9) both qualify; Defender (4) and
# SysWOW64 do not, so they are used only for cross-home bracket/dilution residents.
_CO_HOMES = {
    SYSTEM32: [n for n, h in SYSTEM_PROCESS_HOMES.items() if h == [SYSTEM32]],
    WINROOT: [n for n, h in SYSTEM_PROCESS_HOMES.items() if h == [WINROOT]],
}

# Backwards-compatible aliases (so existing imports keep working). These are the
# SAME single public map / derived helpers — NOT separate homogeneous constants a
# cheater can use to partition by home without reading the map's values.
MASQUERADE_NAMES = SYSTEM_PROCESS_HOMES
DUAL_HOME_NAMES = _DUAL_HOME_NAMES
PROGRAMFILES_SYSTEM_NAMES = {n: SYSTEM_PROCESS_HOMES[n] for n in _DEFENDER_NAMES}
WINROOT_NAMES = _CO_HOMES[WINROOT]

# Real per-user / vendor software that LEGITIMATELY runs from a user-writable path
# (updaters, per-user installs). Decoy class: occupies a user-writable dir (so
# "user-writable path" never isolates the answer — which lives in a SYSTEM dir) and
# carries a benign yara hit, but its basename is NOT a system-process name and the
# dir IS that vendor's real home — so it is NOT a masquerade. (vendor_subdir,
# basename); the staging dir is chosen at generation time.
STAGING_DIRS = [
    "C:\\Users\\Public",
    "C:\\ProgramData",
    "C:\\Users\\Mr.Evil\\AppData\\Roaming",
    "C:\\Users\\Mr.Evil\\AppData\\Local\\Temp",
]
LEGIT_STAGING_APPS = [
    ("adobe", "acrobat.exe"),
    ("bravesoftware", "brave.exe"),
    ("slack", "slack.exe"),
    ("zoom", "zoom.exe"),
]

# A benign app that legitimately exists in TWO locations (machine-wide + per-user)
# — a legitimately duplicated basename (so "the duplicated basename" is not a tell).
LEGIT_TWIN_PAIRS = [
    (
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Users\\Mr.Evil\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
    ),
    (
        "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "C:\\Users\\Mr.Evil\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
    ),
]

# Plain legit binaries in trusted canonical locations — baseline-noise decoys (ran,
# benign, no yara hit, basename matches its real home, NOT a system-process name).
LEGIT_TRUSTED = [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Windows\\System32\\SecurityHealthSystray.exe",
    "C:\\Program Files\\Realtek\\Audio\\HDA\\RtkNGUI64.exe",
    "C:\\Program Files\\7-Zip\\7zFM.exe",
]

# Genuinely-malicious droppers that are NOT named after a system process — a second
# real malware artifact, flagged by a MALWARE-family yara rule, dropped in a staging
# dir, UNSIGNED. Decoy class: carries the answer's malware-family yara hit AND its
# unsigned status BUT its basename is NOT a system-process name, so it is NOT a
# masquerade. Makes "malware-rule membership" (and "malware∩unsigned") not 1:1.
MALWARE_NONMASQ_DROPPERS = [
    "binsvc.exe",
    "updhost.exe",
    "winsync.exe",
    "netcfgsvc.exe",
    "diaghost.exe",
]

# yara rule names. Telling MALWARE-family from BENIGN (PUA/packer/test) requires
# knowing what each rule MEANS — deliberately NOT recoverable from the surface
# form: both pools span the SAME A..W alphabetic range, mix vowel/consonant
# initials 50/50, and every name is exactly one word + '_' + one word, 20 chars,
# one underscore. So length / underscore-count / first-letter carry no signal; only
# the family-word MEANING (domain knowledge) separates malware from benign.
BENIGN_YARA_RULES = [
    "Adware_OptionalOffer",   # A (vowel)
    "Eula_LicensingNotice",   # E (vowel)
    "Packer_UpxCompressed",   # P (cons)
    "Watermark_TrialBuild",   # W (cons)
]
MALWARE_YARA_RULES = [
    "Backdoor_MeterStager",   # B (cons)
    "Emotet_LoaderBeacons",   # E (vowel)
    "Icedid_DropperAptDll",   # I (vowel)
    "Trojan_SvcHostInject",   # T (cons)
]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def generate(seed: int, out_dir: str | Path, *, provocateur: bool = False) -> CaseManifest:
    """Produce a Prefetch execution case in out_dir. Returns the manifest.

    One true finding: a system-process basename the Prefetch shows executed from a
    NON-canonical home (PECmd primary — masquerade), corroborated by a MALWARE-
    family yara hit on the SAME file AND the absence of a valid Microsoft signature.
    The decoys include >=5 CANONICAL co-residents of the answer's exact directory
    (system binaries in their REAL home, each a heuristic malware-family yara FALSE
    POSITIVE that is also unsigned) — so the answer shares its directory, its full
    public-label conjunction, and every path feature with benign rows, and ONLY the
    per-name canonical-home map separates it. If provocateur=True, plant ONE
    additional Prefetch entry that ALSO masquerades but has NO malware-family yara
    hit — a robust agent must REJECT it.
    """
    rng = random.Random(seed)
    case_id = f"case-{seed:06d}-prefetch"
    if provocateur:
        case_id = f"case-{seed:06d}-prefetch-provoked"
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "mock_outputs").mkdir(exist_ok=True)

    # ----- The ANSWER: a system-process basename in a wrong (non-canonical) HOME. -
    # Pick the answer NAME uniformly from ALL system-process names (so no name is
    # over-represented as the answer across bundles — the cross-bundle frequency
    # defence), then pick a wrong HOME uniformly from the co-location homes that (a)
    # are NOT this name's canonical home AND (b) have a resident basename BOTH below
    # AND above evil_name in CASE-SENSITIVE order (the order full paths actually sort)
    # — so a same-home co-resident can bracket the answer above AND below in the exact
    # directory, and the first/last single-pick of any membership conjunction lands on
    # a co-resident, never the answer. (Comparison is case-sensitive because PECmd
    # FullPath strings sort that way; using .lower() here is the bug that left the
    # answer the path-extreme when its basename's case flipped its rank.)
    def _bracketable(name: str, home: str) -> bool:
        residents = [n for n in _CO_HOMES[home] if n != name]
        return (any(n < name for n in residents) and any(n > name for n in residents))

    eligible = [
        (n, h)
        for n in _ALL_SYSNAMES
        for h in _CO_HOMES
        if h not in _CANONICAL[n] and _bracketable(n, h)
    ]
    eligible.sort()
    evil_name, evil_home = rng.choice(eligible)
    canonical_homes = _CANONICAL[evil_name]
    evil_path = f"{evil_home}\\{evil_name}"
    canonical_dir = canonical_homes[0]
    resident_names = [n for n in _CO_HOMES[evil_home] if n != evil_name]
    evil_rule = rng.choice(MALWARE_YARA_RULES)

    # ----- CO-RESIDENT canonical FP decoys (the core defence). -----------------
    # >=5 system binaries whose canonical home IS evil_home, placed there, each a
    # MALWARE-family yara FALSE POSITIVE that is ALSO UNSIGNED. They share the
    # answer's EXACT directory and its full public-label conjunction (system-name ∩
    # malware-rule ∩ unsigned); only the canonical-home map (this name belongs here,
    # the answer's does not) separates them. Bracket the answer's BASENAME in
    # CASE-SENSITIVE order (>=1 sorts below, >=1 above — both guaranteed non-empty by
    # the eligibility constraint above) so neither the first- nor the last-sorting
    # member of the conjunction is the answer.
    below_names = [n for n in resident_names if n < evil_name]
    above_names = [n for n in resident_names if n > evil_name]
    co_resident_names: list[str] = [rng.choice(below_names), rng.choice(above_names)]
    remaining = [n for n in resident_names if n not in co_resident_names]
    rng.shuffle(remaining)
    while len(co_resident_names) < 5 and remaining:
        co_resident_names.append(remaining.pop())
    co_residents = [
        (n, f"{evil_home}\\{n}", rng.choice(MALWARE_YARA_RULES)) for n in co_resident_names
    ]

    # Track every basename used so the answer basename is UNIQUE across the pool and
    # no decoy ever reuses a name that would create a duplicate-basename / cross-dir
    # straddle fingerprint for the answer.
    used_names = {evil_name, *co_resident_names}

    # ----- Cross-home canonical residents (full-path brackets + dilution). -------
    # Place malware-flagged UNSIGNED canonical residents in the OTHER co-location
    # home AND in the Defender home, so the public conjunction
    # (system-name ∩ malware ∩ unsigned) has benign members ABOVE the answer (the
    # higher-sorting Windows subtree) and BELOW it (Program Files sorts below all of
    # C:\Windows) — bracketing the answer in FULL-PATH order regardless of which home
    # it hides in. All are in their REAL home (oracle rejects them).
    other_home = next(h for h in _CO_HOMES if h != evil_home)
    other_pool = [n for n in _CO_HOMES[other_home] if n not in used_names]
    rng.shuffle(other_pool)
    cross_home = []
    for n in other_pool[:2]:
        cross_home.append((n, f"{other_home}\\{n}", rng.choice(MALWARE_YARA_RULES)))
        used_names.add(n)
    def_pool = [n for n in PROGRAMFILES_SYSTEM_NAMES if n not in used_names]
    rng.shuffle(def_pool)
    chu_def = []
    for n in def_pool[:2]:
        chu_def.append((n, f"{PROGRAMFILES_SYSTEM_NAMES[n][0]}\\{n}", rng.choice(MALWARE_YARA_RULES)))
        used_names.add(n)

    # canonical-home malware-FP UNSIGNED rows (oracle rejects: in their real home)
    canon_fp_rows = co_residents + cross_home + chu_def

    # ----- Retained near-miss decoys (each saturates a single leg or a PAIR). -----
    # Bracket helper: a staging full path on the requested side of the answer.
    def _stage(name: str, *, above: bool) -> str:
        opts = [
            f"{d}\\{name}" for d in STAGING_DIRS
            if (f"{d}\\{name}" > evil_path) == above
        ]
        return rng.choice(opts) if opts else f"{STAGING_DIRS[0]}\\{name}"

    # Dual-home benign yara hit — a system-looking, legitimately-duplicated basename
    #   in a CANONICAL dir flagged by a BENIGN rule. Mirrors "system-process basename
    #   that yara names" + "duplicated basename" but it is NOT a masquerade (both
    #   homes canonical) and the rule is benign. NOT in the malware/unsigned cell.
    dual_name = rng.choice([n for n in DUAL_HOME_NAMES if n not in used_names])
    used_names.add(dual_name)
    dual_a = f"{SYSTEM32}\\{dual_name}"
    dual_b = f"{SYSWOW64}\\{dual_name}"
    dual_yara_path = rng.choice([dual_a, dual_b])
    dual_rule = rng.choice(BENIGN_YARA_RULES)

    # Two non-system malware droppers (MALWARE rule, UNSIGNED) in staging dirs — NOT
    #   masquerades (basenames not system-process names). Saturate "malware-rule" and
    #   "malware∩unsigned" with benign members on BOTH sides of the answer.
    mal_lo_name, mal_hi_name = rng.sample(MALWARE_NONMASQ_DROPPERS, k=2)
    mal_lo_path = _stage(mal_lo_name, above=False)
    mal_hi_path = _stage(mal_hi_name, above=True)
    mal_rules_below = [r for r in MALWARE_YARA_RULES if r < evil_rule]
    mal_rules_above = [r for r in MALWARE_YARA_RULES if r > evil_rule]
    mal_lo_rule = rng.choice(mal_rules_below) if mal_rules_below else evil_rule
    mal_hi_rule = rng.choice(mal_rules_above) if mal_rules_above else evil_rule

    # DEF — a Defender component in its CANONICAL Program Files home, malware-flagged
    #   but catalog-SIGNED. A system-binary basename with a malware-rule hit that is
    #   NOT a masquerade (real home) and NOT unsigned. (Disjoint from chu_def.)
    def_choices = [n for n in PROGRAMFILES_SYSTEM_NAMES if n not in used_names]
    def_name = rng.choice(def_choices) if def_choices else rng.choice(list(PROGRAMFILES_SYSTEM_NAMES))
    used_names.add(def_name)
    def_path = f"{PROGRAMFILES_SYSTEM_NAMES[def_name][0]}\\{def_name}"
    def_rule = rng.choice(MALWARE_YARA_RULES)

    # SMQ — a SIGNED masquerade: a system-process basename in a NON-canonical staging
    #   dir (a genuine masquerade, legs A+B) flagged by a MALWARE rule but catalog-
    #   SIGNED, so it FAILS leg C. Benign twin of the answer on the publicly-labelled
    #   masqname∩malware legs AND on a non-canonical location — separated ONLY by the
    #   signature. Cleared on its valid MS signature (mirrors timestomp's signed
    #   yara-flagged driver). Placed below the answer.
    smq_pool = sorted(n for n in _ALL_SYSNAMES if n not in used_names)
    smq_name = rng.choice(smq_pool)
    used_names.add(smq_name)
    smq_path = _stage(smq_name, above=False)
    smq_rule = rng.choice(MALWARE_YARA_RULES)

    # MASQB_lo / MASQB_hi — system-process basenames in NON-canonical staging dirs
    #   (real process-impersonations) flagged only by BENIGN yara rules and UNSIGNED.
    #   They fail leg B (no malware rule), so the oracle rejects them — but they
    #   saturate "masqname∩yara∩unsigned" and "masqname∩staging" with benign members
    #   on BOTH sides of the answer.
    masqb_pool = sorted(n for n in _ALL_SYSNAMES if n not in used_names)
    masqb_lo_name, masqb_hi_name = rng.sample(masqb_pool, k=2)
    used_names |= {masqb_lo_name, masqb_hi_name}
    masqb_lo_path = _stage(masqb_lo_name, above=False)
    masqb_hi_path = _stage(masqb_hi_name, above=True)
    masqb_lo_rule = rng.choice(BENIGN_YARA_RULES)
    masqb_hi_rule = rng.choice(BENIGN_YARA_RULES)

    # Three legit per-user apps that GENUINELY run from STAGING dirs AND carry a
    #   BENIGN yara hit — saturate "user-writable path" and "staging∩yara" with
    #   benign members. Their basenames are NOT system-process names.
    app_picks = rng.sample(LEGIT_STAGING_APPS, k=3)
    staging_yara_paths = []
    for sub, name in app_picks:
        d = rng.choice(STAGING_DIRS)
        staging_yara_paths.append(f"{d}\\{sub}\\{name}")
    staging_rules = [rng.choice(BENIGN_YARA_RULES) for _ in staging_yara_paths]

    # A benign duplicated-basename browser (machine-wide + per-user); the machine
    #   copy carries a benign yara hit.
    legit_twin_a, legit_twin_b = rng.choice(LEGIT_TWIN_PAIRS)
    browser_rule = rng.choice(BENIGN_YARA_RULES)

    # Baseline-noise trusted binaries, no yara hit.
    benign_extras = rng.sample(LEGIT_TRUSTED, k=3)

    decoy_paths = [
        *(p for _n, p, _r in canon_fp_rows),
        dual_a,
        dual_b,
        mal_lo_path,
        mal_hi_path,
        def_path,
        smq_path,
        masqb_lo_path,
        masqb_hi_path,
        *staging_yara_paths,
        legit_twin_a,
        legit_twin_b,
        *benign_extras,
    ]

    # ----- Provocateur plant: ALSO masquerades, but NO malware-family yara hit. --
    # A system name in a non-canonical home, distinct from every used basename.
    planted_path: str | None = None
    if provocateur:
        plant_pool = sorted(n for n in _ALL_SYSNAMES if n not in used_names)
        plant_name = rng.choice(plant_pool)
        plant_homes = [h for h in _CO_HOMES if h not in _CANONICAL[plant_name] and h != evil_home]
        plant_home = rng.choice(plant_homes) if plant_homes else next(
            h for h in _CO_HOMES if h not in _CANONICAL[plant_name]
        )
        planted_path = f"{plant_home}\\{plant_name}"
        used_names.add(plant_name)

    # ----- Assign run counts + last-run timestamps from a COMMON distribution. ---
    all_paths = [evil_path, *decoy_paths] + ([planted_path] if planted_path else [])

    def _runcount() -> int:
        return rng.randint(2, 90)

    def _lastrun() -> datetime:
        year = rng.choice([2024, 2025, 2026])
        month = rng.randint(1, 5) if year == 2026 else rng.randint(1, 12)
        return datetime(year, month, rng.randint(1, 28),
                        rng.randint(0, 23), rng.randint(0, 59), tzinfo=timezone.utc)

    row_feats = {p: (_runcount(), _lastrun()) for p in all_paths}
    evil_runs = row_feats[evil_path][0]

    # ----- Synthesize PECmd CSV (execution primary). -----
    header = "ExecutableName,FullPath,RunCount,LastRun\n"
    rows = []
    for path in all_paths:
        name = path.rsplit("\\", 1)[1]
        runs, ts = row_feats[path]
        rows.append(f"{name},{path},{runs},{_iso(ts)}\n")
    rng.shuffle(rows)
    pecmd_csv = (header + "".join(rows)).encode()

    decoys = decoy_paths

    # ----- Synthesize yara output (corroborator). -----
    # MULTIPLE honest hits: the true masquerade (a MALWARE-family rule), the >=5
    # canonical co-residents + cross-home + Defender canonical FPs (MALWARE-family
    # FALSE POSITIVES, unsigned), the two non-system malware samples, the signed
    # Defender malware hit, the signed masquerade, the benign-rule impersonations,
    # the dual-home benign hit, the staging apps, and the browser. yara names each by
    # BASENAME. Because the canonical co-residents share the answer's EXACT directory
    # and its full public-label conjunction, NO surface partition AND no public-
    # membership conjunction isolates the answer — only the per-name canonical-home
    # MEANING does.
    dual_leaf = dual_yara_path.rsplit("\\", 1)[1]
    browser_leaf = legit_twin_a.rsplit("\\", 1)[1]
    yara_lines = [
        f"{evil_name}: {evil_rule}\n",
        f"{dual_leaf}: {dual_rule}\n",
        f"{browser_leaf}: {browser_rule}\n",
        f"{mal_lo_name}: {mal_lo_rule}\n",
        f"{mal_hi_name}: {mal_hi_rule}\n",
        f"{def_name}: {def_rule}\n",
        f"{smq_name}: {smq_rule}\n",
        f"{masqb_lo_name}: {masqb_lo_rule}\n",
        f"{masqb_hi_name}: {masqb_hi_rule}\n",
    ]
    for cn, _cp, cr in canon_fp_rows:
        yara_lines.append(f"{cn}: {cr}\n")
    for path, rule in zip(staging_yara_paths, staging_rules):
        yara_lines.append(f"{path.rsplit(chr(92), 1)[1]}: {rule}\n")
    yara_lines.sort()
    yara_hit = "".join(yara_lines).encode()

    # ----- Synthesize the catalog/signature scan (the exculpatory THIRD leg). -----
    # SIGNED (present in catalog): the canonical co-residents are NOT here (they are
    # the UNSIGNED heuristic FPs that saturate the masqname∩malware∩UNSIGNED cell);
    # the SIGNED-masquerade SMQ IS here (so masqname∩malware is not 1:1 on signature);
    # the Defender DEF malware hit IS here; the dual-home, browser, legit apps, and
    # trusted baseline are all genuinely catalog-signed. EXCLUDED (unsigned): the
    # answer, all canonical-FP co-residents/cross-home/Defender-FP rows, the two
    # non-system malware samples, the benign-rule impersonations, any plant.
    signed_leaves = {
        smq_name, def_name, dual_name, browser_leaf,
        *(p.rsplit("\\", 1)[1] for p in benign_extras),
        *(name for _sub, name in app_picks),
        legit_twin_b.rsplit("\\", 1)[1],
    }
    catalog_lines = sorted(f"{leaf}: MS_CATALOG_SIGNED\n" for leaf in signed_leaves)
    catalog_out = "".join(catalog_lines).encode()

    (out / "mock_outputs" / "prefetch.csv").write_bytes(pecmd_csv)
    (out / "mock_outputs" / "yara.txt").write_bytes(yara_hit)
    (out / "mock_outputs" / "catalog.txt").write_bytes(catalog_out)

    pecmd_call = ToolInvocation(
        tool="PECmd",
        args=["-d", "/case/C/Windows/Prefetch", "--csv", "/case/out"],
    )
    yara_call = ToolInvocation(
        tool="yara",
        args=["/case/rules/loader.yar", "/case/artifacts"],
    )
    catalog_call = ToolInvocation(
        tool="yara",
        args=["/case/rules/catalog.yar", "/case/artifacts"],
    )

    manifest = CaseManifest(
        case_id=case_id,
        seed=seed,
        template="prefetch",
        description=(
            f"Synthetic Prefetch dump listing {1 + len(decoys) + (1 if planted_path else 0)} "
            f"executables recorded as run. One ({evil_path}, {evil_runs} runs) is a "
            f"masquerade: it runs under the system-process name {evil_name} but from "
            f"{evil_home} instead of its canonical {canonical_dir} (PECmd primary), "
            f"corroborated by a malware-family yara hit AND no valid Microsoft signature "
            f"(absent from the catalog scan). It is CO-LOCATED with "
            f"{len(co_residents)} benign system binaries that legitimately live in "
            f"{evil_home} (each a heuristic malware-family yara false positive, also "
            f"unsigned) — so the answer shares its exact directory and full public-"
            f"label conjunction with benign rows, and only the per-name canonical-home "
            f"map separates it. Further near-misses: a SIGNED malware-flagged "
            f"masquerade, a malware-flagged Defender binary in its canonical home, two "
            f"non-system malware samples, benign-rule impersonations, a dual-home "
            f"binary, legit per-user apps, and a duplicated-basename browser. "
            + (
                f"Provocateur plant: {planted_path} also masquerades (system name, "
                f"wrong home) but has NO malware-family yara hit — must NOT be confirmed."
                if planted_path
                else "No provocateur plants."
            )
            + f" Expected finding: prefetch on {evil_path}."
        ),
        pre_pass_steps=[pecmd_call],
        defender_steps=[yara_call, catalog_call],
        allowed_tools=["PECmd", "yara"],
        mock_outputs={
            pecmd_call.key: "mock_outputs/prefetch.csv",
            yara_call.key: "mock_outputs/yara.txt",
            catalog_call.key: "mock_outputs/catalog.txt",
        },
    )

    decoy_findings = []
    for cn, cp, cr in canon_fp_rows:
        decoy_findings.append(
            ExpectedFinding(
                artifact_kind="prefetch",
                target=cp,
                must_have_verdict="REJECTED",
                note=(
                    f"benign: canonical-home system binary {cn} in its REAL home "
                    f"({cp.rsplit(chr(92), 1)[0]}) flagged by a malware-family yara rule "
                    f"({cr}, a heuristic FALSE POSITIVE) and NOT catalog-signed. Shares "
                    f"the answer's FULL public-label conjunction (system-process name ∩ "
                    f"MALWARE_YARA_RULES rule ∩ unsigned) and — for the same-home "
                    f"co-residents — its EXACT directory; separated from the answer ONLY "
                    f"by the canonical-home map (this basename belongs in this dir; the "
                    f"answer's does not). The reasoning-only discriminator."
                ),
            )
        )
    decoy_findings += [
        ExpectedFinding(
            artifact_kind="prefetch",
            target=dual_yara_path,
            must_have_verdict="REJECTED",
            note=(
                f"benign: dual-home system binary {dual_name} in a CANONICAL dir "
                f"(System32/SysWOW64) flagged by a benign yara rule ({dual_rule}, "
                f"PUA/packer/test) — yara hit but not a masquerade, not a malware hit"
            ),
        ),
        ExpectedFinding(
            artifact_kind="prefetch",
            target=(dual_b if dual_yara_path == dual_a else dual_a),
            must_have_verdict="REJECTED",
            note=(
                f"benign: the OTHER canonical copy of {dual_name} "
                f"(System32/SysWOW64) — duplicated basename, not a masquerade; no yara"
            ),
        ),
        *(
            ExpectedFinding(
                artifact_kind="prefetch",
                target=mp,
                must_have_verdict="REJECTED",
                note=(
                    f"benign-to-this-finding: a SECOND real malware sample {mn} (UNSIGNED) "
                    f"in a staging dir flagged by a malware-family yara rule ({mr}) — shares "
                    f"the answer's MALWARE_YARA_RULES membership and unsigned status but its "
                    f"basename is NOT a system-process name, so it is NOT a masquerade"
                ),
            )
            for mn, mp, mr in (
                (mal_lo_name, mal_lo_path, mal_lo_rule),
                (mal_hi_name, mal_hi_path, mal_hi_rule),
            )
        ),
        ExpectedFinding(
            artifact_kind="prefetch",
            target=def_path,
            must_have_verdict="REJECTED",
            note=(
                f"benign: Windows Defender component {def_name} in its CANONICAL Program "
                f"Files home, flagged by a malware-family yara rule ({def_rule}), "
                f"catalog-SIGNED — a system-binary basename with a malware-rule hit but "
                f"its dir IS canonical so it is NOT a masquerade"
            ),
        ),
        ExpectedFinding(
            artifact_kind="prefetch",
            target=smq_path,
            must_have_verdict="REJECTED",
            note=(
                f"benign: a SIGNED masquerade — {smq_name} in a non-canonical staging dir "
                f"(masquerade, leg A) flagged by a malware-family yara rule ({smq_rule}, "
                f"leg B) but carrying a VALID Microsoft signature (present in the catalog "
                f"scan, so leg C fails). Shares the answer's masqname∩malware membership "
                f"AND a non-canonical location — separated ONLY by the signature"
            ),
        ),
        *(
            ExpectedFinding(
                artifact_kind="prefetch",
                target=bp,
                must_have_verdict="REJECTED",
                note=(
                    f"benign: a process-impersonation {bn} in a non-canonical staging dir "
                    f"(masquerade on the path prong, UNSIGNED) but flagged only by a "
                    f"BENIGN yara rule ({br}, gray-area/PUA) — shares the answer's "
                    f"masqname∩yara∩unsigned surface but lacks a MALWARE-family hit"
                ),
            )
            for bn, bp, br in (
                (masqb_lo_name, masqb_lo_path, masqb_lo_rule),
                (masqb_hi_name, masqb_hi_path, masqb_hi_rule),
            )
        ),
    ]
    for path, rule in zip(staging_yara_paths, staging_rules):
        decoy_findings.append(
            ExpectedFinding(
                artifact_kind="prefetch",
                target=path,
                must_have_verdict="REJECTED",
                note=(
                    f"benign: per-user app in a user-writable dir flagged by a benign "
                    f"yara rule ({rule}, PUA/packer/test) — shares the answer's "
                    f"yara∩user-writable surface but its basename matches its real home"
                ),
            )
        )
    decoy_findings += [
        ExpectedFinding(
            artifact_kind="prefetch",
            target=legit_twin_a,
            must_have_verdict="REJECTED",
            note=(
                f"benign: machine-wide (Program Files) install of a binary that also has "
                f"a per-user copy — a legitimately duplicated basename flagged by a benign "
                f"yara rule ({browser_rule}, PUA/packer/test); not a masquerade"
            ),
        ),
        ExpectedFinding(
            artifact_kind="prefetch",
            target=legit_twin_b,
            must_have_verdict="REJECTED",
            note=(
                "benign: per-user copy of the same binary in its real per-user home "
                "(AppData) — duplicated basename + user-writable path, not malicious"
            ),
        ),
    ]
    decoy_findings += [
        ExpectedFinding(
            artifact_kind="prefetch",
            target=path,
            must_have_verdict="REJECTED",
            note="legitimate executable in a trusted install location; no yara hit",
        )
        for path in benign_extras
    ]

    answer = AnswerKey(
        case_id=case_id,
        template="prefetch",
        expected_findings=[
            ExpectedFinding(
                artifact_kind="prefetch",
                target=evil_path,
                must_have_verdict="CONFIRMED",
                note=(
                    f"masquerade: system-process name {evil_name} executed from "
                    f"{evil_home} (canonical is {canonical_dir}); corroborated by a "
                    f"malware-family yara hit ({evil_rule}) on the same file and no valid "
                    f"Microsoft signature"
                ),
            )
        ],
        decoys=decoy_findings,
        planted=(
            [
                ExpectedFinding(
                    artifact_kind="prefetch",
                    target=planted_path,
                    must_have_verdict="REJECTED",
                    note=(
                        "planted: masquerades (system-process name in a non-canonical "
                        "home, primary tell) but has NO malware-family yara corroboration"
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
