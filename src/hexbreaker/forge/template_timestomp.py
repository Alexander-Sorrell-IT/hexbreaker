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
    # 1 evil + 14 decoys (+ up to 2 planted) are sampled without replacement. ---
    names = rng.sample(DRIVER_NAMES, k=17)
    evil_name = names[0]
    decoy_names = names[1:15]
    plant_pool = names[15:]

    # --- The timestomped file: $SI backdated YEARS before the true $FN. The $FN
    # year (2026) is the SHARED, plurality value: many benign decoys carry $FN
    # year 2026 too (built below), and the evil $FN lands in the MIDDLE of the
    # year (months 5-8) so the answer is INTERIOR on the $FN timestamp axis — it
    # is neither the oldest nor the newest in the 2026 bucket. That kills the
    # absolute-$FN-date frequency tells (max-$FN-year bucket + oldest-in-bucket,
    # and $FN-year MODE within any label subset): the 2026 bucket holds several
    # benign rows older AND newer than the answer, so no $FN-year extremum/mode
    # isolates it. ---
    si_year = rng.randint(2017, 2019)
    si_created = _d(si_year, rng.randint(1, 12), rng.randint(1, 28))
    fn_created = _d(2026, rng.randint(5, 8), rng.randint(1, 28))
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

    # D1 — MAX-GAP BAIT (yara-CLEAN, SIGNED): a genuinely ancient SIGNED driver
    # whose $FN was relinked by a volume op, giving a backward gap even LARGER
    # than the evil row. It owns "max gap overall" and "oldest $SI" (so those
    # rankings miss the answer). Benign: signed AND yara-clean — fails both
    # categorical legs.
    n = decoy_names[0]
    d1_si = _d(2009, rng.randint(1, 12), rng.randint(1, 28))
    # $FN 2026 but EARLIER in the year than the evil $FN (months 1-3, evil is 5-8),
    # so D1 sits OLDER-than-answer inside the shared 2026 $FN bucket — it is one of
    # the older 2026 rows the "max-$FN-year, oldest-in-bucket" tell lands on.
    d1_fn = _d(2026, rng.randint(1, 3), rng.randint(1, 28))
    _add(n, d1_si, d1_fn, False, True,
         "ancient SIGNED driver, $FN relinked by a volume op: largest backward gap, oldest $SI; signed + no yara")

    # D2 — MAX-GAP-IN-YARA BAIT (yara-HIT, SIGNED): a SIGNED driver that the noisy
    # yara rule still flags, with a backward gap LARGER than the evil row AND a $FN
    # at least as recent as the evil row's. So BOTH "max gap among yara-flagged
    # rows" AND "newest $FN among yara-flagged rows" land HERE, not the answer.
    # Benign: it is validly signed — fails leg C.
    n = decoy_names[1]
    d2_si = _d(2012, rng.randint(1, 12), rng.randint(1, 28))
    # $FN 2026, LATER in the year than the evil $FN (months 9-12), so D2 is the
    # newest $FN among yara rows AND a NEWER-than-answer member of the 2026 bucket.
    d2_fn = _d(2026, rng.randint(9, 12), rng.randint(1, 28))
    _add(n, d2_si, d2_fn, True, True,
         "old SIGNED driver, largest gap + newest $FN in the yara set, yara-flagged; benign because validly signed")

    # D3 — MAX-GAP-IN-UNSIGNED BAIT (yara-CLEAN, UNSIGNED): an UNSIGNED file with a
    # backward gap LARGER than the evil row AND a $FN at least as recent. So BOTH
    # "max gap among unsigned rows" AND "newest $FN among unsigned rows" land HERE.
    # Benign: no yara corroboration — fails leg B.
    n = decoy_names[2]
    d3_si = _d(2013, rng.randint(1, 12), rng.randint(1, 28))
    # $FN 2026, LATER in the year than the evil $FN (months 9-12), so D3 is the
    # newest $FN among unsigned rows AND a NEWER-than-answer member of both the
    # overall and the unsigned 2026 $FN buckets.
    d3_fn = _d(2026, rng.randint(9, 12), rng.randint(1, 28))
    _add(n, d3_si, d3_fn, False, False,
         "UNSIGNED file, largest gap + newest $FN among unsigned rows, NO yara hit; benign because uncorroborated")

    # D4 — SUB-THRESHOLD NEAR-MISS (yara-HIT, UNSIGNED), $SI in the EVIL's year
    # band: matches BOTH categorical legs (yara + unsigned) but the gap is months
    # — under the backdate threshold. The closest near-miss, distinguished ONLY by
    # gap magnitude. Its $SI year equals the evil row's, so "rare $SI year" can
    # never isolate the answer.
    n = decoy_names[3]
    d4_si = _d(si_year, rng.randint(1, 6), rng.randint(1, 28))
    d4_fn = d4_si + timedelta(days=rng.randint(150, BACKDATE_DAYS - 20))
    _add(n, d4_si, d4_fn, True, False,
         "in-year reinstall ($SI same year band as evil): yara+unsigned but gap UNDER threshold")

    # D5 — SUB-THRESHOLD SKEW (yara-HIT, UNSIGNED): minute/hour-scale benign skew
    # that matches both categorical legs but is far under threshold. Pads the
    # yara∩unsigned bucket so it is never a 1:1 leak.
    n = decoy_names[4]
    d5_fn = _d(2024, rng.randint(1, 12), rng.randint(1, 28))
    d5_si = d5_fn - timedelta(hours=rng.randint(1, 20))
    _add(n, d5_si, d5_fn, True, False,
         "clock skew: $SI hours before $FN, yara+unsigned but gap << threshold")

    # D6 — CLEAN SIGNED BASELINE (yara-CLEAN, SIGNED): an ordinary recent signed
    # driver with a minute-scale provisioning skew. Pads the signed bucket and the
    # not-yara bucket so neither is structurally unique.
    n = decoy_names[5]
    d6_fn = _d(2022, rng.randint(1, 12), rng.randint(1, 28))
    d6_si = d6_fn - timedelta(minutes=rng.randint(2, 50))
    _add(n, d6_si, d6_fn, False, True,
         "ordinary signed driver, minute-scale provisioning skew; benign on every leg")

    # D7, D8 — MORE SUB-THRESHOLD yara+UNSIGNED near-misses. They share the answer's
    # two categorical legs (yara-flagged AND unsigned) but stay UNDER the backdate
    # threshold, so the `yara ∩ unsigned` 2-feature set has several benign members
    # besides the answer — echoing that set is a low-precision guess, not a 1:1
    # leak. Distinguished from the answer ONLY by gap magnitude.
    n = decoy_names[6]
    # $FN 2026, LATER in the year than the evil $FN (months 9-12), $SI in 2025 so
    # the gap stays UNDER threshold (a recent reinstall). This is the FIFTH
    # unsigned-$FN-2026 row: it pads the unsigned-2026 $FN-year bucket to 5
    # members {answer, D3, D10, D14, D7}, so the "$FN-year MODE among unsigned
    # rows" tell selects a size-5 set (F1 = 2/6 = 1/3, the binding floor) rather
    # than isolating the answer with a few benign rows.
    d7_fn = _d(2026, rng.randint(9, 12), rng.randint(1, 28))
    d7_si = d7_fn - timedelta(days=rng.randint(60, BACKDATE_DAYS - 30))
    _add(n, d7_si, d7_fn, True, False,
         "recent reinstall: yara+unsigned, $SI 2025 months before a 2026 $FN but under threshold")

    n = decoy_names[7]
    d8_fn = _d(2023, rng.randint(1, 12), rng.randint(1, 28))
    d8_si = d8_fn - timedelta(minutes=rng.randint(2, 50))
    _add(n, d8_si, d8_fn, True, False,
         "provisioning skew: yara+unsigned, $SI minutes before $FN; gap << threshold")

    # --- OVER-THRESHOLD PADDING (D9-D14). The backdate threshold (BACKDATE_DAYS)
    # is PUBLICLY DOCUMENTED, so a cheater can condition on `gap > threshold` for
    # FREE without reconstructing the two categorical legs. That makes the
    # OVER-THRESHOLD SUBSET its own attack surface: if the answer is the unique
    # extreme of that subset on ANY ranking (smallest gap, newest $SI, oldest $FN)
    # or its sole member in a band, a single argmin/argmax/oldest/newest restricted
    # to `gap>threshold` isolates it — the exact leak the hunter found
    # (`argmin(gap | gap>365d)` and `$SI-band ∩ over-threshold`). So the over-set
    # must itself be cheat-resistant: the answer is INTERIOR on every axis, and the
    # two over-set 2-feature echoes (`over∩yara`, `over∩unsigned`) each hold >=5
    # rows. D1/D2/D3 already own the over-set's MAX gap / oldest $SI / newest $FN;
    # D9-D14 add benign over-threshold rows that are NEWER-$SI, SMALLER-gap, and
    # OLDER-$FN than the answer, so no over-set ranking lands on it. Each still
    # fails >=1 categorical leg, so the oracle (`over AND yara AND unsigned`) stays
    # a singleton. Realistic: legit System32 drivers are routinely years old with
    # $SI predating $FN from image-deploy / volume ops.

    # D9 — NEWEST-$SI BAIT (yara-HIT, SIGNED): $SI in 2020-2021, NEWER than the
    # evil $SI (<=2019), with $FN 2026. So "newest $SI among over-threshold rows"
    # lands HERE, not the answer. Benign: validly signed.
    n = decoy_names[8]
    # $SI pinned to 2021 (not 2020-21): this row anchors a benign $SI-year-2021
    # cluster {D9, D11, D13} within the yara set (and {D10, D12, D14} within the
    # unsigned set), each of size 3 — strictly larger than the answer's $SI-year
    # bucket (size 2: {answer, D4} share the 2017-19 band). So the "$SI-year MODE"
    # tell within yara / within unsigned lands on the benign 2021 cluster, NOT the
    # answer. 2021 is still the NEWEST $SI in the over-set (answer's $SI <= 2019).
    d9_si = _d(2021, rng.randint(1, 12), rng.randint(1, 28))
    # $FN 2026 but EARLIER in the year than the evil $FN (months 1-3): an
    # OLDER-than-answer member of the 2026 bucket (so "oldest in the max-$FN-year
    # bucket" lands on a benign 2026 row, not the answer).
    d9_fn = _d(2026, rng.randint(1, 3), rng.randint(1, 28))
    _add(n, d9_si, d9_fn, True, True,
         "recently-imaged SIGNED driver, $SI 2020-21 (newest $SI in the over-set), yara-flagged; benign because signed")

    # D10 — NEWEST-$SI BAIT (yara-CLEAN, UNSIGNED): mirror of D9 in the unsigned
    # set, so "newest $SI among unsigned over-threshold rows" also misses the
    # answer. Benign: no yara corroboration.
    n = decoy_names[9]
    d10_si = _d(2021, rng.randint(1, 12), rng.randint(1, 28))
    # $FN 2026 but EARLIER in the year than the evil $FN (months 1-3): an
    # OLDER-than-answer member of BOTH the overall and the unsigned 2026 buckets.
    d10_fn = _d(2026, rng.randint(1, 3), rng.randint(1, 28))
    _add(n, d10_si, d10_fn, False, False,
         "recently-imaged UNSIGNED file, $SI 2021 (newest $SI among unsigned), NO yara; benign because uncorroborated")

    # D11 — SMALLEST-GAP / OLDEST-$FN BAIT (yara-HIT, SIGNED): $SI 2021-22, $FN
    # 2024 — still over threshold (gap ~2-3yr) but UNCONDITIONALLY smaller than the
    # evil gap (>=6yr) AND with $FN older than the evil's 2026 $FN. So BOTH
    # "smallest gap among over-threshold rows" AND "oldest $FN among over-threshold
    # rows" land HERE. Benign: validly signed.
    n = decoy_names[10]
    d11_si = _d(2021, rng.randint(1, 12), rng.randint(1, 28))
    d11_fn = _d(2024, rng.randint(1, 12), rng.randint(1, 28))
    _add(n, d11_si, d11_fn, True, True,
         "old SIGNED driver, $SI 2021 -> $FN 2024 (smallest gap + oldest $FN in the over-set), yara-flagged; benign because signed")

    # D12 — SMALLEST-GAP / OLDEST-$FN BAIT (yara-CLEAN, UNSIGNED): mirror of D11 in
    # the unsigned set, so the smallest-gap / oldest-$FN rankings miss the answer
    # there too. Benign: no yara corroboration.
    n = decoy_names[11]
    d12_si = _d(2021, rng.randint(1, 12), rng.randint(1, 28))
    d12_fn = _d(2023, rng.randint(1, 12), rng.randint(1, 28))
    _add(n, d12_si, d12_fn, False, False,
         "old UNSIGNED file, $SI 2021 -> $FN 2023 (smallest gap among unsigned), NO yara; benign because uncorroborated")

    # D13 — OVER∩YARA PADDER (yara-HIT, SIGNED): a fourth benign over-threshold
    # yara-hit driver so the `over ∩ yara` 2-feature echo holds >=5 rows (answer +
    # D2 + D9 + D11 + D13) and is never a 1:1 leak. Benign: validly signed.
    n = decoy_names[12]
    # $SI pinned to 2021 (was 2014-16): third member of the benign yara $SI-2021
    # cluster {D9, D11, D13}, so the "$SI-year MODE among yara rows" tell lands on
    # this benign cluster (size 3 > the answer's size-2 band), never the answer.
    d13_si = _d(2021, rng.randint(1, 12), rng.randint(1, 28))
    # $FN 2026, LATER than the evil $FN (months 9-12): a NEWER-than-answer benign
    # yara member of the overall 2026 $FN bucket, so that bucket has benign rows
    # on BOTH sides of the answer.
    d13_fn = _d(2026, rng.randint(9, 12), rng.randint(1, 28))
    _add(n, d13_si, d13_fn, True, True,
         "old SIGNED driver, $SI predates $FN from image deploy, yara-flagged; benign because signed (pads over∩yara)")

    # D14 — OVER∩UNSIGNED PADDER (yara-CLEAN, UNSIGNED): a fourth benign
    # over-threshold unsigned file so the `over ∩ unsigned` 2-feature echo holds
    # >=5 rows (answer + D3 + D10 + D12 + D14). Benign: no yara corroboration.
    n = decoy_names[13]
    # $SI pinned to 2021 (was 2014-16): third member of the benign UNSIGNED $SI-
    # 2021 cluster {D10, D12, D14}, so the "$SI-year MODE among unsigned rows" tell
    # lands on this benign cluster (size 3 > the answer's size-2 band), not the
    # answer.
    d14_si = _d(2021, rng.randint(1, 12), rng.randint(1, 28))
    # $FN 2026, LATER than the evil $FN (months 9-12): a NEWER-than-answer benign
    # UNSIGNED member of the 2026 $FN bucket. Together with D3, D7, D10 this makes
    # the unsigned-$FN-2026 bucket = {answer, D3, D7, D10, D14} = 5 (mode tell ->
    # F1 1/3) and gives the overall 2026 bucket benign rows newer than the answer.
    d14_fn = _d(2026, rng.randint(9, 12), rng.randint(1, 28))
    _add(n, d14_si, d14_fn, False, False,
         "old UNSIGNED file, $SI predates $FN from a volume op, NO yara; benign because uncorroborated (pads over∩unsigned)")

    # Sanity (DETERMINISM-safe assertions that pin the 3-axis cheat-resistance
    # shape; if any fails the case is structurally leaky):
    for _nm, _p, si, fn, _lm, _y, _s, _note in decoys:
        assert si < fn  # every row diverges and runs backward
    # No decoy satisfies the full 3-way oracle (gap>thr AND yara AND unsigned):
    for _nm, _p, si, fn, _lm, y, s, _note in decoys:
        assert not (is_timestomped(si, fn) and y and (not s))
    # A SIGNED yara-hit decoy (D2) owns the max gap WITHIN the yara set:
    assert is_timestomped(d2_si, d2_fn) and (d2_fn - d2_si) > (fn_created - si_created)
    # An UNSIGNED yara-clean decoy (D3) owns the max gap WITHIN the unsigned set:
    assert is_timestomped(d3_si, d3_fn) and (d3_fn - d3_si) > (fn_created - si_created)
    # A decoy owns the max gap OVERALL and the oldest $SI (D1):
    assert (d1_fn - d1_si) > (fn_created - si_created) and d1_si < si_created
    # Each categorical bucket has >=2 members (incl. the answer where applicable):
    n_yara = 1 + sum(1 for *_x, y, _s, _nt in decoys if y)          # answer is yara
    n_unsigned = 1 + sum(1 for *_x, _y, s, _nt in decoys if not s)  # answer is unsigned
    assert n_yara >= 2 and (len(decoys) + 1) - n_yara >= 2
    assert n_unsigned >= 2 and (len(decoys) + 1) - n_unsigned >= 2

    # --- OVER-THRESHOLD-SUBSET cheat-resistance (the leak the hunter found). The
    # 365-day threshold is public, so the over-set is its own attack surface; pin
    # the answer as INTERIOR on every over-set ranking so no argmin/argmax/oldest/
    # newest restricted to `gap>threshold` isolates it. ---
    over = [(si, fn, y, s) for _nm, _p, si, fn, _lm, y, s, _note in decoys
            if is_timestomped(si, fn)]
    evil_gap = fn_created - si_created
    # SMALLEST gap in the over-set is a DECOY (D11/D12 have gap << evil_gap):
    assert any((fn - si) < evil_gap for si, fn, _y, _s in over), "no over-decoy with gap < answer"
    # NEWEST $SI in the over-set is a DECOY (D9/D10 have $SI > evil $SI):
    assert any(si > si_created for si, _fn, _y, _s in over), "no over-decoy with $SI newer than answer"
    # OLDEST $FN in the over-set is a DECOY (D11/D12 have $FN < evil $FN):
    assert any(fn < fn_created for _si, fn, _y, _s in over), "no over-decoy with $FN older than answer"
    # The over-set's two 2-feature echoes each hold >=5 rows (answer + >=4 benign),
    # so `over∩yara` and `over∩unsigned` are low-precision guesses, not 1:1 leaks:
    over_yara = 1 + sum(1 for si, fn, y, _s in over if y)             # answer is over+yara
    over_unsigned = 1 + sum(1 for si, fn, _y, s in over if not s)     # answer is over+unsigned
    assert over_yara >= 5 and over_unsigned >= 5
    # >=3 DISTINCT singleton $SI years remain in the over-set (D1/D2/D3 at
    # 2009/2012/2013), so "rarest $SI year" never collapses to {answer}:
    over_si_years = [si.year for si, _fn, _y, _s in over] + [si_created.year]
    _yc = collections.Counter(over_si_years)
    assert sum(1 for v in _yc.values() if v == 1) >= 3, "fewer than 3 singleton $SI years in over-set"

    # --- $FN ($Created0x30) absolute-date tells (the leg the design had left to
    # vary freely). The answer's $FN year (2026) must be a SHARED, plurality value
    # with the answer INTERIOR on the $FN-timestamp axis, else "$FN-year MODE
    # within a label subset" or "oldest-2 in the max-$FN-year bucket" isolates it.
    allrows = [(si_created, fn_created, True, False)] + [
        (si, fn, y, s) for _nm, _p, si, fn, _lm, y, s, _note in decoys
    ]
    # Unsigned-$FN-2026 bucket holds >=5 rows (answer + D3/D7/D10/D14), so the
    # "$FN-year MODE among unsigned rows" tell selects a size->=5 set -> F1 <= 1/3:
    unsigned_fn2026 = sum(1 for _si, fn, _y, s in allrows if (not s) and fn.year == 2026)
    assert unsigned_fn2026 >= 5, f"unsigned $FN-2026 bucket has {unsigned_fn2026} rows (<5)"
    # The overall max-$FN-year bucket (2026) has >=2 benign rows OLDER than the
    # answer by full $FN timestamp (D1/D9/D10 at months 1-3, evil at 5-8), so the
    # "oldest-2 in the max-$FN-year bucket" tell lands on benign rows, not {answer}:
    max_fn_year = max(fn.year for _si, fn, _y, _s in allrows)
    assert max_fn_year == fn_created.year
    older_in_bucket = sum(
        1 for _si, fn, _y, _s in allrows if fn.year == max_fn_year and fn < fn_created
    )
    assert older_in_bucket >= 2, f"only {older_in_bucket} benign $FN-2026 rows older than answer"
    # $SI-year MODE: a benign $SI-year cluster (D9/D11/D13 = 2021) is STRICTLY
    # larger than the answer's $SI-year bucket within BOTH the yara set and the
    # unsigned set, so the "$SI-year MODE" tell lands on the benign cluster:
    ans_si_year = si_created.year
    for restrict in (lambda y, s: y, lambda y, s: not s):  # yara set, unsigned set
        yc = collections.Counter(
            si.year for si, _fn, y, s in allrows if restrict(y, s)
        )
        ans_count = yc[ans_si_year]
        assert max(yc.values()) > ans_count, (
            "answer $SI year is the (tied) MODE within a label subset"
        )

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
