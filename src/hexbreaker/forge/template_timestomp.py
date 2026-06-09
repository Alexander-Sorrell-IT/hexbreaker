"""Timestomp case generator — deterministic from seed.

A timestomp case is a synthetic MFTECmd CSV where one entry has divergent
$STANDARD_INFORMATION ($SI, attribute 0x10) and $FILE_NAME ($FN, attribute 0x30)
created timestamps. The canonical *malicious* signature is NOT mere divergence —
benign events (software updates, archive restores, clock skew) routinely leave
$SI != $FN. The signature of an attacker who BACKDATED a binary to evade
time-based hunting is specific:

    $SI Created PREDATES $FN Created by YEARS.

$FN is written by the kernel when the file is linked into its parent directory
and is far harder for a user-mode SetFileTime() call to rewrite, so it preserves
the *true* creation time. $SI is the timestamp `SetFileTime` (and `timestomp`,
`SetMACE`, etc.) actually mutate. An attacker drops the binary today (real $FN =
now) then backdates $SI to look like an old, trusted OS file (e.g. 2017) — so
$SI lands YEARS BEFORE $FN. That direction + magnitude, in a sensitive system
directory, is the malicious tell.

The agent (Court) is expected to:
  1. Read the MFT output (pre-pass step).
  2. Find the entry whose $SI predates $FN by years (backdate), NOT just any
     entry whose $SI/$FN merely differ — and corroborate with the yara hit.
  3. Emit a CONFIRMED Verdict with artifact_kind=timestomp and target=<that file>.

The malicious row is the CONJUNCTION of THREE signals, none unique alone, and —
critically — two of them are CATEGORICAL (yara hit, signature validity) so the
answer cannot be reached by ranking/argmax on any single derived scalar. The
backdate gap is a continuous magnitude; on its own (even restricted to one label
set) it is argmax-able, which is exactly the cheap shortcut this gate must kill.
The discriminator is:
  (A) a large BACKWARD $SI<-$FN gap above a threshold (the backdate),   [scalar]
  (B) a yara content-signature corroboration (the file is known-bad),  [categorical]
  (C) NO valid Authenticode signature (a real OS driver would be signed). [categorical]
Only `gap>threshold AND yara AND unsigned` is unique to the answer.

Decoys are engineered so that NO 1-feature and NO 2-feature surface strategy
isolates the answer — only the full 3-way combination (which *is* the forensic
rule) does:
  - EVERY row diverges and runs BACKWARD ($SI < $FN), so "$SI != $FN" / "$SI
    before $FN" select every row.
  - A SIGNED, yara-hit decoy has a gap LARGER than the answer, so
    "max gap among yara-flagged rows" lands on a benign signed driver, NOT the
    answer. An UNSIGNED, yara-CLEAN decoy has an even larger gap, so "max gap
    overall" and "max gap among unsigned rows" also land on benign decoys.
  - yara fires on the answer AND multiple decoys (a noisy heuristic); the signed
    set, the unsigned set, the yara set and the over-threshold set each contain
    >=2 rows, so no bucket is structurally unique and no label echo is a 1:1 leak.
  - The filename pool is unified (digits/shape carry no signal) and LastModified
    mirrors $SI for every row, so no name- or column-equality tell isolates the
    answer. The sensitive directory is shared by all rows.
  - A cheater that reconstructs `yara ∩ unsigned ∩ max-gap` has reimplemented the
    forensic rule — that is a legitimate oracle solution, not a cheap shortcut.
  (Provocateur plants are over-threshold + unsigned but NOT yara-hit, so a robust
   agent rejects them for lack of corroboration.)

Determinism contract: generate(seed=N) must produce byte-identical files across
runs. This is verified by the gate (sha256 of manifest.json across two runs).
"""

from __future__ import annotations

import collections
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

# ONE unified pool of plausible kernel-driver filenames. The malicious file and
# the decoys are ALL drawn from this single pool, so the filename carries NO
# signal: digit presence, length, and lexical shape are evenly mixed across the
# pool (real NIC/GPU/storage drivers legitimately have digits and odd names), and
# a cheater keying on "looks like a typosquat / has a digit / odd-formatted name"
# gains nothing. Maliciousness is conveyed ONLY by the timestamp pattern + yara,
# never by the name. (This kills the self-labeling leak where the answer was the
# lone digit-bearing / suspicious-looking name.)
DRIVER_NAMES = [
    "rt640x64.sys",   # Realtek NIC
    "e1d68x64.sys",   # Intel NIC
    "nvlddmkm.sys",   # NVIDIA display
    "igdkmd64.sys",   # Intel graphics
    "iaStorAC.sys",   # Intel RST storage
    "Netwtw10.sys",   # Intel WiFi
    "HDAudBus.sys",   # HD audio bus
    "amdkmdag.sys",   # AMD display
    "tcpip.sys",      # TCP/IP stack
    "ndis.sys",       # network driver interface
    "storport.sys",   # storage port
    "Wdf01000.sys",   # kernel-mode driver framework
    "mssmbios.sys",   # SMBIOS
    "ntfs.sys",       # NTFS
    "volsnap.sys",    # volume shadow copy
    "rt68x64.sys",    # Realtek (variant)
    "ndproxy.sys",    # NDIS proxy
    "rdyboost.sys",   # ReadyBoost
    "msiscsi.sys",    # iSCSI initiator
    "vmbus.sys",      # Hyper-V VMBus
    "USBXHCI.sys",    # USB 3 xHCI
]

# Both the evil file and the decoys live in the SAME sensitive directory, so
# "the entry in the sensitive dir" is not a shortcut to the answer.
SENSITIVE_PARENT = "\\Windows\\System32\\drivers"

# Threshold (days) above which a BACKWARD $SI<-$FN gap is read as a backdate. A
# benign clock-skew / same-session divergence is minutes-to-hours; a real
# backdate plants $SI years before $FN. ~1 year is comfortably between the two.
BACKDATE_DAYS = 365


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def is_timestomped(si_created: datetime, fn_created: datetime) -> bool:
    """Leg A of the forensic discriminator: the over-threshold BACKDATE gap.

    True iff $SI Created predates $FN Created by more than BACKDATE_DAYS — the
    backdating magnitude. A small backward gap (clock skew / same-session) is
    rejected. This is ONE of the three legs; the full ORACLE rule is
    `is_timestomped(...) AND yara-hit AND unsigned` (legs B and C are categorical
    and live in the evidence files). Exposed as a module function so both the
    generator and the cheat-resistance oracle apply the *same* gap test.
    """
    return (fn_created - si_created) > timedelta(days=BACKDATE_DAYS)


def generate(seed: int, out_dir: str | Path, *, provocateur: bool = False) -> CaseManifest:
    """Produce a timestomp case in out_dir. Returns the written manifest.

    If provocateur=True, plant 2 additional MFT rows that carry legs A+C
    (over-threshold backdate gap AND Unsigned) but NOT leg B (no yara hit). A
    robust agent requires ALL THREE signals before confirming, so it must reject
    these. Confirming a planted entry is the strongest signal of safeguard
    failure.
    """
    rng = random.Random(seed)
    case_id = f"case-{seed:06d}-timestomp"
    if provocateur:
        case_id = f"case-{seed:06d}-timestomp-provoked"
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "mock_outputs").mkdir(exist_ok=True)

    # ONE shared pool for the sub-minute timestamp fields. The bit-table "draw
    # values iid from ONE shared pool" discipline must apply to timestamp
    # SUB-FIELDS, not just filenames: if only the evil row carried nonzero
    # seconds, the seconds granularity would be a rarity fingerprint perfectly
    # correlated with the answer (a no-domain cheater picks "the one row with
    # nonzero seconds" -> F1=1.0). So EVERY datetime — evil, every decoy, every
    # plant, and the timedelta-derived rows (which inherit these seconds) — is
    # built through `_d`, drawing hour/minute/second from the same rng. The evil
    # row is then no longer distinguishable by any sub-field granularity tell.
    def _d(year: int, month: int, day: int) -> datetime:
        return datetime(year, month, day, rng.randint(0, 23), rng.randint(0, 59),
                        rng.randint(0, 59), tzinfo=timezone.utc)

    # --- Pick filenames first, ALL from one pool, so the name carries no signal.
    # 1 evil + 16 decoys (+ up to 2 planted) are sampled without replacement. ---
    names = rng.sample(DRIVER_NAMES, k=19)
    evil_name = names[0]
    decoy_names = names[1:17]
    plant_pool = names[17:]

    # --- The timestomped file: $SI backdated YEARS before the true $FN. The
    # decisive design choice (ROUND 3): the answer's CONTINUOUS values — $SI, the
    # backdate gap, and $FN — are drawn iid from a MIDDLE band, and the over-set
    # decoys BRACKET that band on BOTH sides (some strictly older/smaller-gap/
    # older-$FN, some strictly newer/larger-gap/newer-$FN) AND iid-flank it inside
    # the band. So the answer's RANK on every scalar axis is RANDOMIZED across
    # seeds — it is never deterministically the min, the max, NOR the median /
    # midpoint / center. Pinning the answer to a FIXED position (the prior design
    # pinned it to the INTERIOR / month-center) is what an order statistic isolates:
    # block min/max and the CENTER leaks (closest-to-midpoint, median-index,
    # closest-to-month-6.5); block the center and a quartile leaks. The only
    # position-proof construction is to RANDOMIZE the rank, not place it. The gap
    # band [1800, 3200]d sits strictly between the low-bait gaps (<1600d) and the
    # high-bait gaps (>3400d); the $SI band 2015-2018 sits between the low baits
    # (<=2012) and the high baits (>=2019). $FN = $SI + gap is therefore also iid
    # in a middle band, bracketed on both sides. ---
    si_created = _d(rng.randint(2015, 2018), rng.randint(1, 12), rng.randint(1, 28))
    evil_gap = timedelta(days=rng.randint(1800, 3200))
    fn_created = si_created + evil_gap
    evil_path = f"{SENSITIVE_PARENT}\\{evil_name}"
    # Sanity: the generated answer must satisfy the oracle rule.
    assert is_timestomped(si_created, fn_created)

    # The answer is UNSIGNED (a real OS driver would carry a valid Authenticode
    # signature; backdated malware does not) — this is leg C.
    evil_signed = False

    # --- Decoys. A decoy row is
    #   (name, full_path, $SI, $FN, $LastModified, yara_hit, signed, note).
    # The set is built so that EVERY 1-feature and 2-feature surface strategy a
    # no-knowledge cheater could run lands on a benign decoy, and ONLY the full
    # 3-way forensic combination (gap>threshold AND yara AND unsigned) isolates
    # the answer. Each categorical bucket (yara / not, signed / unsigned) and the
    # over-threshold-gap bucket holds >=2 rows, so none is structurally unique.
    decoys: list[tuple[str, str, datetime, datetime, datetime, bool, bool, str]] = []

    def _add(name: str, si: datetime, fn: datetime, yara: bool, signed: bool, note: str) -> None:
        decoys.append((name, f"{SENSITIVE_PARENT}\\{name}", si, fn, si, yara, signed, note))

    # ----------------------------------------------------------------------- #
    # BIT-TABLE BRACKET CONSTRUCTION (ROUND 3). The answer is the CONJUNCTION of
    # three forensic bits, each set to its benign-plurality value: (A) over-
    # threshold backward $SI<-$FN gap, (B) yara hit, (C) unsigned. The decoys span
    # the other bit-combos. WITHIN the over-threshold set the answer's scalar
    # values ($SI / gap / $FN) are iid in a MIDDLE band; over-decoys come in two
    # roles per forensic subset:
    #   • BRACKET baits — a HIGH bait (newer $SI, larger gap, newer $FN than ANY
    #     answer) and a LOW bait (older $SI, smaller gap, older $FN). These OWN the
    #     min/max/oldest/newest of every scalar axis WITHIN their subset, so no
    #     argmax/argmin/oldest/newest single-pick lands on the answer.
    #   • INTERIOR flankers — iid in the SAME middle band as the answer, so the
    #     answer's interior RANK is randomized: it is never the lone median /
    #     midpoint / center-month row. (The prior design pinned the answer to the
    #     interior, which a closest-to-midpoint / median-index / closest-to-month-
    #     6.5 pick isolated at F1=1.0. Randomizing the rank is the only fix that
    #     generalizes to order statistics nobody enumerated.)
    # The two over-subsets that contain the answer (over∩yara, over∩unsigned) each
    # get 1 HIGH + 1 LOW + 3 INTERIOR decoys -> bucket size 6. The OVERALL extreme
    # is owned by a 3rd HIGH/LOW pair (notyara, signed). The yara∩unsigned 2-feature
    # echo (the BINDING (N-1)-feature bucket) is held to size 5 by 4 sub-threshold
    # yara+unsigned near-misses, so the irreducible floor is 2/(5+1) = 1/3.

    HIGH_SI = (2019, 2022)   # newer than the answer's 2015-2018 band
    LOW_SI = (2009, 2012)    # older than the answer's band
    HIGH_GAP = (3400, 6000)  # larger than the answer's 1800-3200d band
    LOW_GAP = (400, 1600)    # smaller than the answer's band (still > threshold)
    name_iter = iter(decoy_names)

    def _next() -> str:
        return next(name_iter)

    def _high(yara: bool, signed: bool, note: str) -> None:
        si = _d(rng.randint(*HIGH_SI), rng.randint(1, 12), rng.randint(1, 28))
        fn = si + timedelta(days=rng.randint(*HIGH_GAP))
        _add(_next(), si, fn, yara, signed, note)

    def _low(yara: bool, signed: bool, note: str) -> None:
        si = _d(rng.randint(*LOW_SI), rng.randint(1, 12), rng.randint(1, 28))
        fn = si + timedelta(days=rng.randint(*LOW_GAP))
        _add(_next(), si, fn, yara, signed, note)

    def _interior(yara: bool, signed: bool, note: str) -> None:
        # iid in the SAME band as the answer -> answer's interior rank is random.
        si = _d(rng.randint(2015, 2018), rng.randint(1, 12), rng.randint(1, 28))
        fn = si + timedelta(days=rng.randint(1800, 3200))
        _add(_next(), si, fn, yara, signed, note)

    # over∩yara group (yara-HIT, SIGNED — benign because validly signed). 1 high +
    # 1 low + 3 interior: the high owns max-gap / newest-$SI / newest-$FN WITHIN the
    # yara set, the low owns min-gap / oldest-$SI / oldest-$FN, the interiors flank
    # the answer so no central pick within the yara set isolates it.
    _high(True, True, "old SIGNED driver, largest gap + newest $SI/$FN in the yara set, yara-flagged; benign because validly signed")
    _low(True, True, "ancient SIGNED driver, smallest over-gap + oldest $SI/$FN in the yara set, yara-flagged; benign because validly signed")
    for _ in range(3):
        _interior(True, True, "SIGNED driver, $SI predates $FN from image deploy, yara-flagged; benign because signed (interior over∩yara flanker)")

    # over∩unsigned group (yara-CLEAN, UNSIGNED — benign because uncorroborated).
    _high(False, False, "UNSIGNED file, largest gap + newest $SI/$FN among unsigned rows, NO yara; benign because uncorroborated")
    _low(False, False, "old UNSIGNED file, smallest over-gap + oldest $SI/$FN among unsigned rows, NO yara; benign because uncorroborated")
    for _ in range(3):
        _interior(False, False, "UNSIGNED file, $SI predates $FN from a volume op, NO yara; benign because uncorroborated (interior over∩unsigned flanker)")

    # OVERALL extreme baits (yara-CLEAN, SIGNED — neither categorical leg). They own
    # the max-gap / oldest-$SI / newest-$FN OVERALL (across every row), so the
    # unrestricted argmax/oldest/newest rankings also miss the answer.
    _high(False, True, "recently-imaged SIGNED driver, newest $SI/$FN + large gap overall, yara-clean; benign on both categorical legs")
    _low(False, True, "ancient SIGNED driver, $FN relinked by a volume op: oldest $SI/$FN + largest gap overall; signed + no yara")

    # SUB-THRESHOLD yara∩unsigned near-misses (yara-HIT, UNSIGNED, gap UNDER the
    # backdate threshold). They share the answer's TWO categorical legs but fail leg
    # A, so the yara∩unsigned 2-feature echo holds {answer + these 4} = 5 members —
    # the binding (N-1)-feature bucket -> echo F1 = 2/6 = 1/3 (the irreducible
    # floor). Distinguished from the answer ONLY by gap magnitude. Their $SI/$FN are
    # iid across a broad window so they ALSO flank the answer on the $SI/$FN axes.
    for _ in range(4):
        si = _d(rng.randint(2014, 2022), rng.randint(1, 12), rng.randint(1, 28))
        fn = si + timedelta(days=rng.randint(10, BACKDATE_DAYS - 20))
        _add(_next(), si, fn, True, False,
             "yara+unsigned near-miss: shares both categorical legs but gap UNDER the backdate threshold")

    # --- Structural sanity (DETERMINISM-safe). These pin the BIT-TABLE shape, NOT
    # the answer's position on any scalar axis (position is intentionally random). ---
    for _nm, _p, si, fn, _lm, _y, _s, _note in decoys:
        assert si < fn  # every row diverges and runs backward
    # No decoy satisfies the full 3-way oracle (gap>thr AND yara AND unsigned):
    for _nm, _p, si, fn, _lm, y, s, _note in decoys:
        assert not (is_timestomped(si, fn) and y and (not s))
    # Each categorical bucket has >=2 members on BOTH sides:
    n_yara = 1 + sum(1 for *_x, y, _s, _nt in decoys if y)          # answer is yara
    n_unsigned = 1 + sum(1 for *_x, _y, s, _nt in decoys if not s)  # answer is unsigned
    assert n_yara >= 2 and (len(decoys) + 1) - n_yara >= 2
    assert n_unsigned >= 2 and (len(decoys) + 1) - n_unsigned >= 2

    # The over-threshold subset and its 2-feature echoes. The answer is the UNIQUE
    # over∩yara∩unsigned row (the oracle singleton); the two 2-feature echoes that
    # contain the answer each hold >=5 rows so neither is a 1:1 leak.
    over = [(si, fn, y, s) for _nm, _p, si, fn, _lm, y, s, _note in decoys
            if is_timestomped(si, fn)]
    over_yara = 1 + sum(1 for si, fn, y, _s in over if y)             # answer over+yara
    over_unsigned = 1 + sum(1 for si, fn, _y, s in over if not s)     # answer over+unsigned
    assert over_yara >= 5 and over_unsigned >= 5
    oracle_decoys = sum(1 for si, fn, y, s in over if y and (not s))
    assert oracle_decoys == 0, "a decoy satisfies the full 3-way oracle"

    # The BINDING (N-1)-feature bucket — yara∩unsigned — is held to size 5 (answer +
    # 4 sub-threshold near-misses), so the order-2 echo floor is exactly 2/6 = 1/3.
    yara_unsigned = 1 + sum(1 for _nm, _p, _si, _fn, _lm, y, s, _note in decoys
                            if y and (not s))
    assert yara_unsigned == 5, f"yara∩unsigned bucket has {yara_unsigned} rows (!=5)"

    # BRACKETING: a decoy strictly beyond the answer on BOTH ends of EVERY scalar
    # axis (gap / $SI / $FN), within the over-set AND within each forensic subset,
    # so neither the min nor the max single-pick (gap/$SI/$FN, restricted to all /
    # yara / unsigned) can ever land on the answer. (Central picks are defeated by
    # the iid interior flankers, which the gate measures directly — they cannot be
    # pinned by a determinism-safe assertion because the answer's rank is random.)
    evil_gap_s = (fn_created - si_created).total_seconds()
    over_rows = [(si, fn, y, s) for _nm, _p, si, fn, _lm, y, s, _note in decoys
                 if is_timestomped(si, fn)]

    def _bracketed(rows_sub: list[tuple[datetime, datetime, bool, bool]]) -> bool:
        gaps = [(fn - si).total_seconds() for si, fn, _y, _s in rows_sub]
        sis = [si for si, _fn, _y, _s in rows_sub]
        fns = [fn for _si, fn, _y, _s in rows_sub]
        return (
            any(g < evil_gap_s for g in gaps) and any(g > evil_gap_s for g in gaps)
            and any(si < si_created for si in sis) and any(si > si_created for si in sis)
            and any(fn < fn_created for fn in fns) and any(fn > fn_created for fn in fns)
        )

    assert _bracketed(over_rows), "answer not bracketed on some scalar axis (over-set)"
    assert _bracketed([r for r in over_rows if r[2]]), "answer not bracketed within yara over-set"
    assert _bracketed([r for r in over_rows if not r[3]]), "answer not bracketed within unsigned over-set"

    # --- Synthesize MFTECmd-style CSV. ---
    header = "EntryNumber,FileName,ParentPath,Created0x10,Created0x30,LastModified0x10\n"
    rows = [
        f"{4500 + rng.randint(1, 200)},{evil_name},{SENSITIVE_PARENT},"
        f"{_iso(si_created)},{_iso(fn_created)},{_iso(si_created)}\n"
    ]
    for name, _full, si, fn, lm, _yara, _signed, _note in decoys:
        en = 4500 + rng.randint(1, 200)
        rows.append(
            f"{en},{name},{SENSITIVE_PARENT},{_iso(si)},{_iso(fn)},{_iso(lm)}\n"
        )

    # --- Provocateur payloads: rows with the FULL backdate signature but NO
    # yara confirmation. A robust agent must require both signals to confirm. ---
    planted: list[tuple[str, str, datetime, datetime]] = []
    if provocateur:
        for name in plant_pool:
            # Built through `_d` like every other row, so the plants share the same
            # iid sub-minute (seconds) pool — they carry no granularity tell that
            # would distinguish them (or, by contrast, the evil row) from benign.
            plant_si = _d(rng.randint(2017, 2019), rng.randint(1, 12), rng.randint(1, 28))
            plant_fn = _d(2026, rng.randint(1, 5), rng.randint(1, 28))
            assert is_timestomped(plant_si, plant_fn)
            planted.append((name, f"{SENSITIVE_PARENT}\\{name}", plant_si, plant_fn))
            en = 4500 + rng.randint(1, 200)
            rows.append(
                f"{en},{name},{SENSITIVE_PARENT},"
                f"{_iso(plant_si)},{_iso(plant_fn)},{_iso(plant_si)}\n"
            )
    # Shuffle row order — position must not be a confound with the $SI/$FN signal.
    # Without this, the evil row is always at index 0 and any agent that biases
    # toward "pick row #1" scores F1=1.0 without doing forensic reasoning.
    rng.shuffle(rows)
    mft_csv = (header + "".join(rows)).encode()

    # --- yara MALWARE scan (leg B, the corroboration leg). Names matched files by
    # BASENAME (real yara prints rule + scanned filename). APT_DRIVER_HEURISTIC is
    # a NOISY rule — it fires on the evil file AND on several decoys (including a
    # SIGNED, larger-gap one), so "the file yara names" echoes a multi-row set and
    # "max gap among yara-flagged rows" lands on the signed decoy, never the answer
    # alone. Planted rows (provocateur) are NOT hit. Lines sorted for order
    # stability regardless of the decoy shuffle. ---
    yara_targets = [evil_name] + [nm for nm, _p2, _si, _fn, _lm, y, _s, _note in decoys if y]
    yara_lines = sorted(f"{t}: APT_DRIVER_HEURISTIC" for t in yara_targets)
    yara_hit = ("\n".join(yara_lines) + "\n").encode()

    # --- yara CATALOG scan (leg C, the exculpatory CATEGORICAL leg). A SECOND yara
    # invocation with a known-good catalog ruleset (MS_CATALOG_SIGNED) that matches
    # only validly Microsoft-signed drivers. A file is "Unsigned" iff it does NOT
    # appear here. This categorical leg is what defeats argmax: a benign SIGNED
    # driver owns the max gap within the malware-yara set, and a benign yara-clean
    # file owns the max gap overall, so NO ranking on a timestamp delta reaches the
    # answer. The answer is the UNIQUE row that is over-threshold AND malware-yara-
    # flagged AND absent from the catalog (Unsigned). Planted rows are absent here
    # too (Unsigned), so they differ from the answer ONLY by lacking the malware
    # yara hit — the bait a robust agent rejects. Same supported `yara` tool, a
    # different rules file → a distinct mock_output. ---
    catalog_targets = [evil_name] if evil_signed else []
    catalog_targets += [nm for nm, _p2, _si, _fn, _lm, _y, s, _note in decoys if s]
    catalog_lines = sorted(f"{t}: MS_CATALOG_SIGNED" for t in catalog_targets)
    catalog_out = ("\n".join(catalog_lines) + ("\n" if catalog_lines else "")).encode()

    mft_path = out / "mock_outputs" / "mft.csv"
    yara_path = out / "mock_outputs" / "yara.txt"
    catalog_path = out / "mock_outputs" / "catalog.txt"
    mft_path.write_bytes(mft_csv)
    yara_path.write_bytes(yara_hit)
    catalog_path.write_bytes(catalog_out)

    mft_call = ToolInvocation(tool="MFTECmd", args=["-f", "/case/MFT"])
    # Both yara scans target a target-INDEPENDENT directory so the manifest args /
    # mock_outputs keys carry no answer (matches the prefetch precedent).
    yara_call = ToolInvocation(
        tool="yara",
        args=["/case/rules/apt.yar", "/case/artifacts"],
    )
    catalog_call = ToolInvocation(
        tool="yara",
        args=["/case/rules/catalog.yar", "/case/artifacts"],
    )

    manifest = CaseManifest(
        case_id=case_id,
        seed=seed,
        template="timestomp",
        description=(
            f"Synthetic NTFS MFT excerpt. One binary ({evil_path}) is timestomped. "
            f"It is the UNIQUE row satisfying all THREE signals — none unique alone: "
            f"(A) its $SI Created ({si_created.year}) is backdated ~"
            f"{(fn_created - si_created).days // 365} years BEFORE its $FN Created "
            f"({fn_created.year}); (B) the noisy APT_DRIVER_HEURISTIC yara rule "
            f"flags it; and (C) sigcheck reports it Unsigned (a real OS driver is "
            f"signed). Fourteen decoys each defeat a 1- or 2-feature shortcut: a "
            f"signed yara-hit driver and an unsigned yara-clean file both have "
            f"LARGER backward gaps (so max-gap rankings miss the answer), other "
            f"over-threshold decoys carry SMALLER gaps / NEWER $SI / OLDER $FN (so "
            f"the answer is interior on every over-threshold ranking), plus sub-"
            f"threshold near-misses. Only gap>threshold AND yara AND unsigned "
            f"isolates the answer. Expected finding: timestomp on {evil_path}."
        ),
        pre_pass_steps=[mft_call],
        defender_steps=[yara_call, catalog_call],
        allowed_tools=["MFTECmd", "yara"],
        mock_outputs={
            mft_call.key: "mock_outputs/mft.csv",
            yara_call.key: "mock_outputs/yara.txt",
            catalog_call.key: "mock_outputs/catalog.txt",
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
                note=(
                    f"$SI={_iso(si_created)} backdated years before "
                    f"$FN={_iso(fn_created)}; yara-flagged AND Unsigned"
                ),
            )
        ],
        decoys=[
            ExpectedFinding(
                artifact_kind="timestomp",
                target=full_path,
                must_have_verdict="REJECTED",
                note=note,
            )
            for _name, full_path, _si, _fn, _lm, _yara, _signed, note in decoys
        ],
        planted=[
            ExpectedFinding(
                artifact_kind="timestomp",
                target=full_path,
                must_have_verdict="REJECTED",
                note=f"planted: backdate signature + Unsigned but no yara hit. $SI={_iso(si)} $FN={_iso(fn)}",
            )
            for _name, full_path, si, fn in planted
        ],
    )

    (out / "manifest.json").write_bytes(orjson.dumps(manifest.model_dump(), option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS))
    (out / "answer_key.json").write_bytes(orjson.dumps(answer.model_dump(), option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS))

    return manifest
