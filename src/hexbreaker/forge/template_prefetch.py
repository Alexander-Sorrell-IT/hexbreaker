"""Prefetch execution case generator — deterministic from seed.

A Prefetch case is a synthetic PECmd CSV (the Windows Prefetch view) listing
executables the OS recorded as having RUN, each with its resolved FullPath, run
count, and last-run time. A `.pf` entry is strong execution evidence: the binary
at that path was launched on this host.

The agent (Court) is expected to:
  1. Read the PECmd dump (pre-pass step).
  2. Identify the entry that is MASQUERADING: a binary whose basename is a known
     Windows system process but whose Prefetch FullPath is NOT that process's
     canonical location (a user-writable staging dir instead) — corroborated by a
     malware-family yara signature hit AND the absence of a valid Microsoft
     Authenticode signature (a real system binary would be catalog-signed).
  3. Emit a CONFIRMED Verdict with artifact_kind="prefetch" and
     target=<that binary's FullPath>.

REASONING-ONLY (cheat-resistance, Option 1): every SURFACE signal that fires on
the answer also fires on >=1 decoy, and the decoys carry benign near-miss tells,
so no cheap shortcut (read a label, run a regex, pick the only-hit/only-oddity
row) isolates the answer. The malicious row is the CONJUNCTION of THREE
meaning-level legs, each saturated by a benign decoy (the timestomp precedent):
  (A) MASQUERADE — a system-process basename whose dir is NOT its canonical home.
  (B) MALWARE-family yara hit (a real content signature, not a benign PUA/packer).
  (C) UNSIGNED — absent from the Microsoft Authenticode/catalog scan.
Every PAIRWISE intersection of these (and of their surface proxies) ALSO fires on
a benign decoy, so no 2-feature membership shortcut isolates the answer:
  - yara hits the answer AND >=1 benign decoy (a correctly-located signed binary
    flagged by a benign PUA/packer rule) — "the file yara names" is not 1:1.
  - The PUBLIC MALWARE_YARA_RULES membership fires on the answer AND on a benign
    decoy (a second malware sample that is NOT a masquerade; a malware-flagged but
    validly-signed system binary in its canonical home) — "malware-rule hit" not 1:1.
  - The PUBLIC MASQUERADE_NAMES membership ∩ a yara hit (even ∩ a MALWARE rule)
    fires on the answer AND on a benign decoy that is in its CANONICAL home (signed)
    OR is a SIGNED masquerade — so masqname∩malware is bracketed, not 1:1; only the
    UNSIGNED leg (C) closes it. A SIGNED system-process basename in a wrong dir,
    even malware-flagged, is a benign near-miss the analyst clears on its valid MS
    signature — exactly as a SIGNED yara-flagged driver is cleared in timestomp.
  - A user-writable path is occupied by the answer AND >=1 benign decoy (real
    software — an updater — that genuinely runs from AppData/ProgramData).
  - A system-process basename appears on the answer AND on a benign decoy in its
    CANONICAL location — so "named like svchost.exe" is not a 1:1 giveaway.
The ONLY discriminator is the MEANING of the 3-way combination: a system-process
basename from a NON-canonical home (T1036.005 masquerade) AND a malware-family
content hit AND no valid code signature. A strategy that reconstructs all three
HAS reimplemented the forensic rule and IS the oracle, not a cheat. This requires
forensic domain knowledge (canonical install locations, malware-family semantics,
signing posture), not a label read or a surface regex.

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
plants ONE entry that ALSO masquerades (system-process basename in a wrong dir,
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

# Known Windows system processes and their CANONICAL directory. A `.pf` entry for
# one of these basenames running from a DIFFERENT directory is the masquerade
# (T1036.005) — the malicious primary signal. The same basename running from its
# canonical dir is benign (and is used as a decoy so "named like a system process"
# is never, on its own, the answer).
SYSTEM32 = "C:\\Windows\\System32"
SYSWOW64 = "C:\\Windows\\SysWOW64"

# System-process basenames whose ONLY legitimate home is System32 — a `.pf` entry
# for one of these from ANY other directory is the masquerade. The answer (and the
# provocateur plant) draws its basename from here. The pool is large enough to give
# each case DISTINCT basenames for the answer + the several masqname near-miss decoys
# (canonical-System32, signed-masquerade, two benign-rule masquerades) + the plant —
# all genuine System32-canonical Windows processes.
MASQUERADE_NAMES = {
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
}

# System binaries that legitimately ship as BOTH a 64-bit (System32) and a 32-bit
# (SysWOW64) copy on an x64 host — so the SAME basename appears in two canonical
# dirs and is NOT a masquerade. The benign-yara decoy is drawn from here: it gives
# yara a SECOND structurally-identical (system-process) basename to name AND a
# second legitimately-duplicated basename — so neither "the system-looking yara
# hit" nor "the duplicated basename" isolates the answer.
DUAL_HOME_NAMES = [
    "rundll32.exe",
    "regsvr32.exe",
    "cmd.exe",
    "wscript.exe",
    "mshta.exe",
]

# System-process-LOOKING binaries whose canonical home is a "C:\Program Files\..."
# subdir (Windows Defender's service host + CLI ship there, NOT in System32). A `.pf`
# entry for one of these from its real Program Files home is NOT a masquerade. They
# are used for the malware-flagged benign near-miss whose canonical home sorts BELOW
# every staging dir — giving the masqname-class∩malware-rule set a member on the LOW
# side of the answer (System32 names sort above it), so that intersection BRACKETS
# the answer instead of leaving it the path-extreme. Telling these apart from the
# answer requires knowing their canonical home (domain knowledge), not a string sort.
PROGRAMFILES_SYSTEM_NAMES = {
    "MpCmdRun.exe": ["C:\\Program Files\\Windows Defender"],
    "MsMpEng.exe": ["C:\\Program Files\\Windows Defender"],
}

# User-writable staging dirs a masquerading binary runs from. The answer's
# system-process basename is placed under one of these (wrong-dir => masquerade).
# All sort BELOW "C:\Windows\System32"/"SysWOW64" (the dual-home + twin benign
# duplicated-basename rows), so the answer is never the path-max duplicated-basename
# row — "the last-sorting duplicated entry" stays a benign System32/SysWOW64 row.
# (These — Public, ProgramData, per-user AppData — are the canonical real-world
# malware staging locations; "C:\Windows\Temp" is deliberately omitted because it
# sorts ABOVE System32 and would make the answer a path-sort outlier.)
STAGING_DIRS = [
    "C:\\Users\\Public",
    "C:\\ProgramData",
    "C:\\Users\\Mr.Evil\\AppData\\Roaming",
    "C:\\Users\\Mr.Evil\\AppData\\Local\\Temp",
]

# Real software that LEGITIMATELY runs from a user-writable path (updaters,
# per-user installs). Decoy class: occupies a STAGING dir (so "user-writable path"
# is not unique to the answer) but its basename is NOT a system-process name and
# the dir IS that vendor's real home — so it is NOT a masquerade. Each is given as
# a (machine-wide, per-user) pair so the basename is also legitimately duplicated.
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

# Real per-user software basenames that LEGITIMATELY run from a user-writable
# path. Decoy class: each is placed UNDER one of the STAGING_DIRS (so it shares the
# answer's exact staging directory — "in a user-writable dir" and even path-sort
# order cannot isolate the answer) but its basename is NOT a system-process name,
# so it is NOT a masquerade. Basenames deliberately SPAN the alphabet so the
# answer's system-process basename is not a lexicographic outlier. Each is given as
# (vendor_subdir, basename); the staging dir is chosen at generation time. ALL
# basenames are lowercase (matching the lowercase system-process names and the
# lowercase dual-home / browser leaves) so a cheater's case-SENSITIVE sort of the
# yara leaves agrees with the case-insensitive basename bracketing below — a
# capitalized leaf would otherwise sort before every lowercase one and make the
# answer's basename the lexicographic max ("yara_lastleaf" leak). Vendor SUBDIRS are
# lowercase too, so a vendor-subdir app's FULL PATH can sort after a bare
# lowercase-system-process path in the same dir (e.g. "...\\zoom\\zoom.exe" >
# "...\\winlogon.exe") — keeping the full-path bracket reliable ("yarasing_last" /
# "staging_last" leak).
LEGIT_STAGING_APPS = [
    ("adobe", "acrobat.exe"),
    ("bravesoftware", "brave.exe"),
    ("google\\update", "googleupdate.exe"),
    ("microsoft\\onedrive", "onedrive.exe"),
    ("slack", "slack.exe"),
    ("microsoft\\teams", "teams.exe"),
    ("zoom", "zoom.exe"),
]

# Plain legit binaries in trusted canonical locations — baseline-noise decoys (ran,
# benign, no yara hit, basename matches its real home).
LEGIT_TRUSTED = [
    "C:\\Windows\\System32\\notepad.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Windows\\System32\\SecurityHealthSystray.exe",
    "C:\\Program Files\\Realtek\\Audio\\HDA\\RtkNGUI64.exe",
    "C:\\Program Files\\7-Zip\\7zFM.exe",
]

# Genuinely-malicious droppers that are NOT named after a system process — a second
# real malware artifact, flagged by a MALWARE-family yara rule, dropped in a staging
# dir. Decoy class: it carries the answer's malware-family yara hit BUT its basename
# is NOT a system-process name (not in MASQUERADE_NAMES / DUAL_HOME_NAMES), so it is
# NOT a masquerade. This makes "the file yara hit with a MALWARE-family rule" no
# longer 1:1 with the answer (a cheater who reads the public MALWARE_YARA_RULES set
# and picks every member-hit now also picks this row) — the answer is separated only
# by the MEANING of the combination (malware hit AND a system-process basename in a
# non-canonical home), never by malware-rule membership alone. Basenames span a..z
# (bracketing the answer's c..w system-process leaf) and are lowercase, matching the
# rest of the leaf vocabulary so they introduce no lexicographic outlier.
MALWARE_NONMASQ_DROPPERS = [
    "binsvc.exe",
    "updhost.exe",
    "winsync.exe",
    "netcfgsvc.exe",
    "diaghost.exe",
]

# yara rule names. Telling MALWARE-family from BENIGN (PUA/packer/test) requires
# knowing what each rule MEANS — it is deliberately NOT recoverable from the rule
# string's surface form. Both pools span the SAME alphabetic range (A..W) and use
# the same UPPER/Mixed style, so neither "the rule that sorts first" nor "the rule
# that sorts last" is biased toward the malicious row. The discriminator is rule
# SEMANTICS (domain knowledge), not lexicographic position.
#   The pools are SURFACE-INDISTINGUISHABLE — telling malware from benign needs the
#   MEANING of the family word, not any string shape:
#     - alphabet: benign initials A..W strictly BRACKET malware initials B..T, so
#       for any malware rule a benign rule sorts before it and one after ("the rule
#       that sorts first/last" always lands on a benign hit);
#     - vowel/consonant initial: BOTH pools are 50/50 vowel/consonant-initial
#       (benign A,E vowel + P,W cons; malware E,I vowel + B,T cons), so "the
#       consonant/vowel-initial rule" is not biased to either;
#     - shape: every name is one word + '_' + one word, EXACTLY one underscore and
#       EXACTLY 20 characters — so length / underscore-count carry no signal either.
BENIGN_YARA_RULES = [
    "Adware_OptionalOffer",   # A (vowel)
    "Eula_LicensingNotice",   # E (vowel)
    "Packer_UpxCompressed",   # P (cons)
    "Watermark_TrialBuild",   # W (cons)
]

# Malware-family rules: a real signature hit. ONLY the true masquerading binary
# gets one of these. Initials B..T sit strictly INSIDE the benign A..W range; the
# pool mixes vowel/consonant initials and matches the 20-char/one-underscore shape.
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

    One true finding: a binary the Prefetch shows executed under a system-process
    basename but from a NON-canonical, user-writable path (PECmd primary —
    masquerade), corroborated by a MALWARE-family yara hit on the SAME file. The
    decoys carry benign near-miss tells (a benign yara hit on a correctly-located
    binary; a legit updater that runs from a staging dir; a system-process binary
    in its canonical home) so no surface feature isolates the answer. If
    provocateur=True, plant ONE additional Prefetch entry that ALSO masquerades
    but has NO malware-family yara hit — a robust agent must REJECT it.
    """
    rng = random.Random(seed)
    case_id = f"case-{seed:06d}-prefetch"
    if provocateur:
        case_id = f"case-{seed:06d}-prefetch-provoked"
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "mock_outputs").mkdir(exist_ok=True)

    # ----- The ANSWER: a System32-only system-process name in a wrong dir. -----
    masq_names = list(MASQUERADE_NAMES)
    evil_name = rng.choice(masq_names)
    canonical_dir = MASQUERADE_NAMES[evil_name][0]  # System32
    evil_dir = rng.choice(STAGING_DIRS)
    # Half the time the dropper nests under a plausible SINGLE-component vendor-style
    # subdir (real masquerades do both: drop in the staging root OR hide inside a
    # fake vendor folder). This makes the answer's path depth/length overlap the
    # benign apps' so "the shortest / shallowest path" is NOT a tell. The subdir is
    # capped to ONE component (the benign apps include TWO-component subdirs, so a
    # benign row is always at least as deep — "the deepest path" stays benign too).
    single_subdirs = [sub for sub, _ in LEGIT_STAGING_APPS if "\\" not in sub]
    evil_subdir = rng.choice(["", *single_subdirs])
    evil_full_dir = f"{evil_dir}\\{evil_subdir}" if evil_subdir else evil_dir
    evil_path = f"{evil_full_dir}\\{evil_name}"
    evil_rule = rng.choice(MALWARE_YARA_RULES)
    # Benign rules that sort BEFORE / AFTER the malware rule, so the malware rule is
    # never the lexicographic extreme of the fired rules — "the rule that sorts
    # first/last" then lands on a benign hit, not the answer. (The benign and
    # malware pools span the same A..W range, so both sides are always non-empty.)
    rules_below = [r for r in BENIGN_YARA_RULES if r < evil_rule]
    rules_above = [r for r in BENIGN_YARA_RULES if r > evil_rule]

    # ----- Near-miss decoys (every surface tell of the answer also fires here). --
    # NOTE: the answer's masquerading binary deliberately has NO System32 "canonical
    # twin". An earlier design added one to dilute yara-echo, but a twin makes the
    # answer's basename the ONLY one that STRADDLES System32 and a user-writable dir
    # — a pure-string `System32`-straddle shortcut then isolates the answer WITHOUT
    # reading yara (bypassing the whole two-tool corroboration). yara already names
    # ~6 basenames with bracketed extremality, so no twin is needed to defeat
    # yara-echo; omitting it removes the straddle tell outright.
    #
    # Decoys 1+2 — a dual-home system binary (legit in BOTH System32 and SysWOW64).
    #   One copy gets a BENIGN yara hit (benign yara #1, CANONICAL). This mirrors
    #   the answer on the "system-process basename that yara names" and "duplicated
    #   basename" features — but it is NOT a masquerade (both dirs are canonical)
    #   and the rule is benign, so those features do not isolate the answer.
    dual_name = rng.choice(DUAL_HOME_NAMES)
    dual_a = f"{SYSTEM32}\\{dual_name}"
    dual_b = f"{SYSWOW64}\\{dual_name}"
    dual_yara_path = rng.choice([dual_a, dual_b])  # the canonical copy yara flags
    # The dual-home benign hit uses a rule that sorts BELOW the malware rule (the
    # browser benign hit, below, uses one that sorts ABOVE) — together they bracket
    # the malware rule so it is never the lexicographic min/max of the fired rules.
    dual_rule = rng.choice(rules_below)

    # ----- MEMBERSHIP near-misses (kill the public-constant-list shortcuts). --------
    # The answer is the CONJUNCTION of THREE meaning-legs: (A) masquerade — a
    # MASQUERADE_NAMES basename in a NON-canonical dir; (B) a MALWARE_YARA_RULES hit;
    # (C) UNSIGNED (absent from the catalog scan). A submitter who knows the open-source
    # constant lists (the threat model grants the MIT Forge) could otherwise pick the
    # answer by reading LABELS alone — basename∈MASQUERADE_NAMES, rule∈MALWARE_YARA_RULES,
    # catalog membership — WITHOUT computing canonical-home meaning. So EVERY single-leg
    # and PAIRWISE-leg label intersection is saturated by a benign decoy, on BOTH sides
    # of the answer in path order, so neither a first- nor last-sorting single pick
    # isolates the answer. Only the full 3-way meaning rule does (that IS the oracle).
    #
    # Bracket helper: place `name` in a staging dir (optionally under a real
    # single-component vendor subdir) whose FULL path sorts on the requested side of
    # the answer. Enumerating (dir, ""|subdir) placements — not just dir roots — is
    # what makes the bracket reliable even when the answer nests under a vendor subdir
    # in the highest-sorting staging dir (e.g. C:\Users\Public\zoom\...): a co-located
    # subdir placement that sorts after/before the answer then always exists. All
    # subdirs are real vendor folders (realistic), so the bracket decoy stays plausible.
    _stage_dirs = [
        f"{d}\\{sub}" if sub else d
        for d in STAGING_DIRS
        for sub in ("", *single_subdirs)
    ]

    def _stage(name: str, *, above: bool) -> str:
        opts = [
            f"{d}\\{name}" for d in _stage_dirs
            if (f"{d}\\{name}" > evil_path) == above and f"{d}\\{name}" != evil_path
        ]
        return rng.choice(opts) if opts else f"{evil_dir}\\{name}"

    # Near-miss MAL_lo / MAL_hi — TWO genuine malware samples (MALWARE_YARA_RULES hit,
    #   UNSIGNED) that are NOT masquerades (basenames not in MASQUERADE_NAMES /
    #   DUAL_HOME_NAMES). They give "malware-rule membership", "yara∩unsigned", and
    #   "malware∩staging" benign members on BOTH sides of the answer — so none of those
    #   single-picks lands on the answer. One sorts below the answer, one above.
    mal_lo_name, mal_hi_name = rng.sample(MALWARE_NONMASQ_DROPPERS, k=2)
    mal_lo_path = _stage(mal_lo_name, above=False)
    mal_hi_path = _stage(mal_hi_name, above=True)
    # Their malware rules bracket evil_rule so the answer's rule is never the lexical
    # extreme of the fired malware rules either (ties fall back to the bracketed path).
    mal_rules_below = [r for r in MALWARE_YARA_RULES if r < evil_rule]
    mal_rules_above = [r for r in MALWARE_YARA_RULES if r > evil_rule]
    mal_lo_rule = rng.choice(mal_rules_below) if mal_rules_below else evil_rule
    mal_hi_rule = rng.choice(mal_rules_above) if mal_rules_above else evil_rule
    #
    # Near-miss SYS — a MASQUERADE_NAMES basename in its CANONICAL System32 home,
    #   flagged by a MALWARE_YARA_RULES rule, catalog-SIGNED. It is NOT a masquerade
    #   (System32 IS its canonical home), so the oracle rejects it. System32 sorts
    #   ABOVE every staging dir, so SYS is the HIGH-side member of the
    #   MASQUERADE_NAMES∩malware-rule set (SMQ, below, is the low side) — bracketing
    #   the answer there. Separated from the answer ONLY by the MEANING of the dir.
    sys_name = rng.choice([n for n in masq_names if n != evil_name])
    sys_path = f"{SYSTEM32}\\{sys_name}"
    sys_rules_above = [r for r in MALWARE_YARA_RULES if r > evil_rule]
    sys_rule = rng.choice(sys_rules_above) if sys_rules_above else evil_rule
    #
    # Near-miss DEF — a system-process-LOOKING Windows Defender component in its
    #   CANONICAL "C:\Program Files\..." home, malware-flagged, catalog-SIGNED. NOT a
    #   masquerade (its real home). Program Files sorts BELOW every staging dir — an
    #   extra LOW-side member of the malware-rule∩hit set.
    def_name = rng.choice(list(PROGRAMFILES_SYSTEM_NAMES))
    def_path = f"{PROGRAMFILES_SYSTEM_NAMES[def_name][0]}\\{def_name}"
    def_rule = rng.choice(MALWARE_YARA_RULES)
    #
    # Near-miss SMQ — a SIGNED masquerade: a MASQUERADE_NAMES basename in a NON-canonical
    #   staging dir (a genuine masquerade, legs A+B) flagged by a MALWARE_YARA_RULES rule
    #   but carrying a VALID signature (present in catalog), so it FAILS leg C. It is the
    #   benign twin of the answer on the two PUBLICLY-LABELLED legs (MASQUERADE_NAMES ∩
    #   MALWARE_YARA_RULES ∩ staging), so that intersection is NOT 1:1 — only the UNSIGNED
    #   leg separates them. Placed BELOW the answer (SYS, System32, above) so the set
    #   brackets the answer. The analyst clears it on its valid MS signature (mirrors
    #   timestomp's signed yara-flagged driver).
    smq_name = rng.choice([n for n in masq_names if n not in (evil_name, sys_name)])
    smq_path = _stage(smq_name, above=False)
    smq_rule = rng.choice(MALWARE_YARA_RULES)
    #
    # Near-miss MASQB_lo / MASQB_hi — TWO MASQUERADE_NAMES basenames in NON-canonical
    #   staging dirs (real process-impersonations) flagged only by BENIGN yara rules
    #   (gray-area tools, not a known malware family) and UNSIGNED. They fail leg B, so
    #   the oracle rejects them — but they populate "MASQUERADE_NAMES∩yara∩unsigned" and
    #   "masqname∩staging" with benign members on BOTH sides of the answer, so those
    #   single-picks never isolate it. One sorts below the answer, one above.
    masqb_lo_name, masqb_hi_name = rng.sample(
        [n for n in masq_names if n not in (evil_name, sys_name, smq_name)], k=2
    )
    masqb_lo_path = _stage(masqb_lo_name, above=False)
    masqb_hi_path = _stage(masqb_hi_name, above=True)
    masqb_lo_rule = rng.choice(BENIGN_YARA_RULES)
    masqb_hi_rule = rng.choice(BENIGN_YARA_RULES)

    # Decoys 4-6 — THREE legit per-user apps that GENUINELY run from STAGING dirs
    #   AND each carry a BENIGN yara hit. They mirror the answer on "in a
    #   user-writable dir AND yara-flagged". The ONLY separator is the MEANING: a
    #   system-process basename in a non-canonical dir + a malware-family rule — not
    #   any surface partition.
    # Pick THREE benign staging apps + their dirs so the answer is NEVER a surface
    # outlier of the staging∩yara set, in EITHER sort order a cheater might use:
    #   - BASENAME bracket: one app's basename sorts < evil_name and one > evil_name,
    #     so the answer's basename is never the min/max yara leaf ("yara_firstleaf"/
    #     "yara_lastleaf" land on a benign app).
    #   - FULL-PATH bracket: one chosen placement sorts < evil_path and one > it, so
    #     "the staging∩yara entry that sorts first/last" is never the answer.
    #   - DIR share: one app sits in the answer's EXACT staging dir.
    # Apps whose basename brackets evil_name (both pools are always non-empty: the
    # app basenames span a..z and evil_name is a c..w system-process name). This is
    # the BASENAME bracket (kills yara_firstleaf/lastleaf, which sort by leaf).
    apps_bn_below = [a for a in LEGIT_STAGING_APPS if a[1].lower() < evil_name.lower()]
    apps_bn_above = [a for a in LEGIT_STAGING_APPS if a[1].lower() > evil_name.lower()]
    app_lo = rng.choice(apps_bn_below)  # basename < evil_name
    app_hi = rng.choice(apps_bn_above)  # basename > evil_name
    app_mid = rng.choice([a for a in LEGIT_STAGING_APPS if a not in (app_lo, app_hi)])
    # FULL-PATH bracket (kills staging_first/last & stgyara_first/last, which sort by
    # full path): place the apps so at least one full path sorts < evil_path and one
    # > evil_path, AND one shares the answer's exact dir. Enumerate every (dir, app)
    # placement, then for each app pick a dir making its full path bracket: app_lo
    # below evil_path (and in the answer's own dir), app_hi above evil_path.
    def _below(app):
        opts = [d for d in STAGING_DIRS if f"{d}\\{app[0]}\\{app[1]}" < evil_path]
        return rng.choice(opts) if opts else evil_dir

    def _above(app):
        opts = [d for d in STAGING_DIRS if f"{d}\\{app[0]}\\{app[1]}" > evil_path]
        return rng.choice(opts) if opts else evil_dir

    # app_lo: prefer the answer's exact dir if that already sorts below; else any
    # below-dir (its basename < evil_name usually already makes it sort below).
    lo_dir = evil_dir if f"{evil_dir}\\{app_lo[0]}\\{app_lo[1]}" < evil_path else _below(app_lo)
    app_placements = [
        (lo_dir, app_lo),
        (_above(app_hi), app_hi),
        (rng.choice(STAGING_DIRS), app_mid),
    ]
    staging_yara_paths = [f"{d}\\{sub}\\{name}" for d, (sub, name) in app_placements]
    staging_rules = [rng.choice(BENIGN_YARA_RULES) for _ in staging_yara_paths]

    # Decoys 7+8 — a benign app that legitimately exists in TWO locations (a
    #   machine-wide Program Files install + a per-user AppData copy). Adds another
    #   duplicated basename and another staging-dir occupant. The Program Files copy
    #   ALSO carries a benign yara hit: that makes it a yara+duplicated-basename row
    #   in C:\Program Files — which sorts BELOW the answer's staging dirs — so the
    #   yara∩duplicated set brackets the answer (a benign member sorts before it,
    #   the System32 twin/dual after it). Not a masquerade.
    legit_twin_a, legit_twin_b = rng.choice(LEGIT_TWIN_PAIRS)
    browser_rule = rng.choice(rules_above)  # sorts ABOVE the malware rule (brackets)

    # Decoys 9+ — ordinary trusted-location binaries, no yara hit. These are pure
    #   baseline noise: they carry NONE of the answer's surface tells (not staged,
    #   not yara-hit, not a system-process basename), so they cannot be confused for
    #   the answer — their only job is to DILUTE the candidate pool, lowering chance
    #   (1/num_candidates) and shrinking the relative weight of any single-pick
    #   position/rarity shortcut that happens to align with the answer on a seed.
    benign_extras = rng.sample(LEGIT_TRUSTED, k=4)

    decoy_paths = [
        dual_a,
        dual_b,
        mal_lo_path,
        mal_hi_path,
        sys_path,
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
    # Its basename avoids evil_name AND every masqname decoy (sys_name in System32;
    # smq_name, masqb_lo/hi in staging dirs) so no MASQUERADE basename straddles
    # System32 and a user dir except by the answer's own (forbidden) design.
    planted_path: str | None = None
    if provocateur:
        used_masq = {evil_name, sys_name, smq_name, masqb_lo_name, masqb_hi_name}
        plant_name = rng.choice([n for n in masq_names if n not in used_masq])
        plant_dir = rng.choice([d for d in STAGING_DIRS if d != evil_dir])
        planted_path = f"{plant_dir}\\{plant_name}"

    # ----- Assign run counts + last-run timestamps from a COMMON distribution. ---
    # The answer must NOT be separable by a surface numeric/temporal feature: every
    # row (answer, decoys, plant) draws its RunCount from one pool and its LastRun
    # year uniformly from {2024,2025,2026}. So "the lowest run count", "the only
    # 2026 entry", "the most recent run" are NOT tells — they land on a decoy as
    # often as on the answer.
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
    # Shuffle so the evil row is not always at index 0 — position must not be a
    # confound with the masquerade signal.
    rng.shuffle(rows)
    pecmd_csv = (header + "".join(rows)).encode()

    # Decoy list (path only — features live in row_feats / the CSV).
    decoys = decoy_paths

    # ----- Synthesize yara output (corroborator). -----
    # MULTIPLE honest hits: the true masquerading binary (a MALWARE-family rule) and
    # several benign decoys (PUA/packer/test rules) — a dual-home system binary in a
    # CANONICAL dir, three per-user apps in STAGING dirs, and the machine-wide
    # browser copy. yara names each by BASENAME (real yara prints the rule + the
    # scanned filename), keeping the full target string out of the sealed bundle
    # contiguously. Because many files are named — including ones that share the
    # answer's staging-dir membership, its system-process-basename shape, and its
    # duplicated-basename status, and ones that bracket it in every sort order — NO
    # surface partition of the yara output (the only-hit, the staging∩yara hit, the
    # system-looking hit, the yara∩duplicated hit, the lexicographically- or
    # path-extreme hit) isolates the answer. The agent must reason about WHICH hit
    # is a MALWARE-family rule on a MASQUERADING binary. Sorted so the malicious line
    # is not pinned to a fixed position.
    dual_leaf = dual_yara_path.rsplit("\\", 1)[1]
    browser_leaf = legit_twin_a.rsplit("\\", 1)[1]
    yara_lines = [
        f"{evil_name}: {evil_rule}\n",
        f"{dual_leaf}: {dual_rule}\n",
        f"{browser_leaf}: {browser_rule}\n",
        # The membership near-misses (each saturates a leg/pair on BOTH sides of the
        # answer): two malware samples that are not masquerades (MAL_lo/hi), a
        # malware-flagged System32 system binary (SYS), a malware-flagged Defender
        # binary in Program Files (DEF), a SIGNED malware-flagged masquerade (SMQ,
        # fails only leg C), and two benign-flagged process-impersonations (MASQB_lo/hi).
        # yara names each by basename — so no single-/two-label intersection isolates
        # the answer; only the full 3-way meaning rule (the oracle) does.
        f"{mal_lo_name}: {mal_lo_rule}\n",
        f"{mal_hi_name}: {mal_hi_rule}\n",
        f"{sys_name}: {sys_rule}\n",
        f"{def_name}: {def_rule}\n",
        f"{smq_name}: {smq_rule}\n",
        f"{masqb_lo_name}: {masqb_lo_rule}\n",
        f"{masqb_hi_name}: {masqb_hi_rule}\n",
    ]
    for path, rule in zip(staging_yara_paths, staging_rules):
        yara_lines.append(f"{path.rsplit(chr(92), 1)[1]}: {rule}\n")
    yara_lines.sort()
    yara_hit = "".join(yara_lines).encode()

    # ----- Synthesize the catalog/signature scan (the exculpatory THIRD leg). -----
    # A SECOND yara invocation against a known-good catalog ruleset (MS_CATALOG_SIGNED)
    # names the basenames of binaries that carry a valid Microsoft Authenticode
    # signature. The answer is ABSENT (unsigned) — leg C. The signed set deliberately
    # INCLUDES the SIGNED-masquerade near-miss SMQ (a masqname in a wrong dir, even
    # malware-flagged) so that "MASQUERADE_NAMES ∩ MALWARE_YARA_RULES" is NOT 1:1: only
    # the UNSIGNED leg separates the answer from SMQ. It also includes the canonical
    # system binaries (SYS, DEF, dual-home), the legit apps, and the trusted baseline —
    # all genuinely catalog-signed. It EXCLUDES the answer, the second malware sample
    # (MAL), the benign gray-area impersonation (MASQ_BENIGN), and any plant — all
    # plausibly unsigned. yara names each by basename (same column-split posture).
    # SIGNED: the canonical system binaries (SYS, DEF, dual-home), the SIGNED
    # masquerade (SMQ — its valid signature is what clears it), the legit apps and the
    # trusted baseline. UNSIGNED (absent): the answer, both extra malware samples
    # (MAL_lo/hi), both benign-rule impersonations (MASQB_lo/hi), and any plant.
    signed_leaves = {
        sys_name, def_name, smq_name, dual_name, browser_leaf,
        *(p.rsplit("\\", 1)[1] for p in benign_extras),
        *(name for _sub, name in (app_lo, app_hi, app_mid)),
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
    # yara scans a target-INDEPENDENT directory (never the evil path) so the
    # manifest's defender_steps args and the mock_outputs key carry no answer.
    yara_call = ToolInvocation(
        tool="yara",
        args=["/case/rules/loader.yar", "/case/artifacts"],
    )
    # The signature/catalog scan is a SECOND yara invocation against a known-good
    # MS catalog ruleset (the timestomp precedent) — distinct args => distinct key.
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
            f"{evil_dir} instead of its canonical {canonical_dir} (PECmd primary), "
            f"corroborated by a malware-family yara hit AND no valid Microsoft signature "
            f"(absent from the catalog scan). Decoys carry benign near-miss tells "
            f"(including a SIGNED malware-flagged masquerade and a malware-flagged "
            f"system binary in its canonical home): {dual_name} appears in both System32 "
            f"and SysWOW64 (a legit dual-home "
            f"binary) and one copy gets a benign yara (PUA/packer) hit; "
            f"{len(staging_yara_paths)} per-user apps run from staging dirs AND get "
            f"benign yara hits (so staging∩yara is not unique to the answer); a "
            f"browser appears machine-wide and per-user (duplicated basename). "
            + (
                f"Provocateur plant: {planted_path} also masquerades (system name, "
                f"wrong dir) but has NO malware-family yara hit — must NOT be confirmed."
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

    decoy_findings = [
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
                    f"basename is NOT a system-process name, so it is NOT a masquerade; not "
                    f"THIS prefetch masquerade finding"
                ),
            )
            for mn, mp, mr in (
                (mal_lo_name, mal_lo_path, mal_lo_rule),
                (mal_hi_name, mal_hi_path, mal_hi_rule),
            )
        ),
        ExpectedFinding(
            artifact_kind="prefetch",
            target=sys_path,
            must_have_verdict="REJECTED",
            note=(
                f"benign: system-process basename {sys_name} in its CANONICAL System32 "
                f"home, flagged by a malware-family yara rule ({sys_rule}) — shares the "
                f"answer's MASQUERADE_NAMES basename AND its malware-rule hit, but the "
                f"dir IS canonical so it is NOT a masquerade; separated from the answer "
                f"ONLY by the meaning of the directory"
            ),
        ),
        ExpectedFinding(
            artifact_kind="prefetch",
            target=def_path,
            must_have_verdict="REJECTED",
            note=(
                f"benign: Windows Defender component {def_name} in its CANONICAL Program "
                f"Files home, flagged by a malware-family yara rule ({def_rule}) — a "
                f"system-binary basename with a malware-rule hit (Program Files sorts "
                f"below the staging answer, the low bracket of masqname-class∩malware), "
                f"but its dir IS canonical so it is NOT a masquerade"
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
                f"scan, so leg C fails). Shares the answer's MASQUERADE_NAMES∩"
                f"MALWARE_YARA_RULES membership AND its staging dir — separated from the "
                f"answer ONLY by the meaning of the signature (cleared on its valid sig)"
            ),
        ),
        *(
            ExpectedFinding(
                artifact_kind="prefetch",
                target=bp,
                must_have_verdict="REJECTED",
                note=(
                    f"benign: a process-impersonation {bn} in a non-canonical staging dir "
                    f"(a masquerade on the path prong, UNSIGNED) but flagged only by a "
                    f"BENIGN yara rule ({br}, gray-area/PUA) — shares the answer's "
                    f"masqname∩yara∩unsigned surface but lacks a MALWARE-family hit, so it "
                    f"is not confirmed malware"
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
                    f"staging∩yara surface but its basename matches its real home; not "
                    f"a masquerade, not a malware hit"
                ),
            )
        )
    decoy_findings += [
        ExpectedFinding(
            artifact_kind="prefetch",
            target=legit_twin_a,
            must_have_verdict="REJECTED",
            note=(
                f"benign: machine-wide (Program Files) install of a binary that also "
                f"has a per-user copy — a legitimately duplicated basename flagged by a "
                f"benign yara rule ({browser_rule}, PUA/packer/test); not a masquerade, "
                f"not a malware hit"
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
                    f"{evil_dir} (canonical is {canonical_dir}); corroborated by a "
                    f"malware-family yara hit ({evil_rule}) on the same file"
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
                        "user-writable dir, primary tell) but has NO malware-family "
                        "yara corroboration"
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
