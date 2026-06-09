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
    # Pool expansion (round 4): more genuine Windows / vendor kernel-driver
    # filenames so the yara and unsigned label subsets carry MORE iid interior
    # flankers. With only 3 interiors per over-subset the answer's CENTRAL ($SI/$FN
    # median/midpoint) rank in the size-10 yara/unsigned sets was diluted to ~1/4
    # and spiked to 0.58 on the K=24 gate seeds by finite-sample variance. Five
    # interiors per subset enlarge those sets so the answer's central rank sits at
    # the irreducible ~1/m with margin. Every added name is a real driver (mixed
    # casing/digits, same morphology grammar as the originals), so the unified-pool
    # anti-tell (name carries no signal) is preserved.
    "disk.sys",       # generic disk class
    "partmgr.sys",    # partition manager
    "volmgr.sys",     # volume manager
    "acpi.sys",       # ACPI
    "pci.sys",        # PCI bus
    "usbhub3.sys",    # USB 3 hub
    "HDAudio.sys",    # HD audio class
    "Rtnicprop64.sys",# Realtek NIC property
    "e2f68.sys",      # Intel NIC (variant)
    "ibtusb.sys",     # Intel Bluetooth USB
    "nvhda64v.sys",   # NVIDIA HD audio
    "TeeDriverW8x64.sys",  # Intel Management Engine
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
    # 1 evil + 20 decoys (+ up to 2 planted) are sampled without replacement.
    # (Round 4: 20 decoys, not 16 — both over-subsets carry 5 interior flankers
    # instead of 3, enlarging the yara/unsigned label sets so the answer's CENTRAL
    # date rank within them dilutes to the irreducible floor.) ---
    # 1 evil + 22 decoys (+ up to 2 planted) sampled without replacement.
    # (ROUND 5: 22 decoys, not 20 — the yara∩unsigned near-miss group grows from 4
    # to 6 so that bucket holds answer + 6 = 7 rows. The extra two near-misses are
    # what let the bucket twin the answer on BOTH the $FN and the $SI absolute-date
    # axes simultaneously: 3 are $FN-twins (their $FN is iid from the answer's $FN
    # distribution) and 3 are $SI-twins (their $SI is iid from the answer's $SI
    # distribution). With only 2+2 the bucket is too small to flank the answer's
    # rank away from the median; 3+3 drives every absolute-date order statistic
    # within the bucket to its ~1/m floor. See the near-miss block below.)
    names = rng.sample(DRIVER_NAMES, k=25)
    evil_name = names[0]
    decoy_names = names[1:23]
    plant_pool = names[23:]

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
    # high-bait gaps (>3400d); the $SI band 2014-2019 sits between the low baits
    # (<=2012) and the high baits (>=2021). $FN = $SI + gap is therefore also iid
    # in a middle band, bracketed on both sides.
    #
    # ROUND 4: the answer's $SI band is drawn from the SAME [2014, 2019] band as the
    # over∩{yara,unsigned} interior flankers, so the answer is a TRUE iid member of
    # the interior $SI population — its $SI RANK within the yara set and the unsigned
    # set is uniformly random, never concentrated near the (lower-)median. The prior
    # narrow [2015, 2018] answer band sat structurally OLD relative to the round-4
    # recent-$SI yara∩unsigned near-misses, pinning the answer at the $SI lower-median
    # of those size-10 sets (medlocol_10_notcatalog F1=0.50). Matching the answer's
    # $SI band to the interior band is the rank-randomization the round-3 design
    # already applies to the gap/$FN axes, now extended to the absolute $SI axis. ---
    si_created = _d(rng.randint(2014, 2019), rng.randint(1, 12), rng.randint(1, 28))
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

    def _high(yara: bool, signed: bool, note: str,
              si_band: tuple[int, int] = HIGH_SI) -> None:
        si = _d(rng.randint(*si_band), rng.randint(1, 12), rng.randint(1, 28))
        fn = si + timedelta(days=rng.randint(*HIGH_GAP))
        _add(_next(), si, fn, yara, signed, note)

    def _low(yara: bool, signed: bool, note: str) -> None:
        si = _d(rng.randint(*LOW_SI), rng.randint(1, 12), rng.randint(1, 28))
        fn = si + timedelta(days=rng.randint(*LOW_GAP))
        _add(_next(), si, fn, yara, signed, note)

    def _interior(yara: bool, signed: bool, note: str,
                  si_band: tuple[int, int] = (2014, 2019)) -> None:
        # iid in a band STRADDLING the answer -> answer's interior rank is random.
        si = _d(rng.randint(*si_band), rng.randint(1, 12), rng.randint(1, 28))
        fn = si + timedelta(days=rng.randint(1800, 3200))
        _add(_next(), si, fn, yara, signed, note)

    # over∩yara group (yara-HIT, SIGNED — benign because validly signed). 1 high +
    # 1 low + 3 interior: the high owns max-gap / newest-$SI / newest-$FN WITHIN the
    # yara set, the low owns min-gap / oldest-$SI / oldest-$FN, the interiors flank
    # the answer so no central pick within the yara set isolates it.
    #
    # ROUND 4: the over∩yara SIGNED interiors' $SI band STRADDLES the answer's
    # 2015-2018 band on BOTH sides (2013-2020), instead of sitting in the answer's
    # own band. The round-4 yara∩unsigned near-misses (built $FN-first around the
    # answer's recent $FN) carry RECENT $SI (>= the answer's), which — without this
    # widening — piled extra rows ABOVE the answer in the size-10 yara set and pinned
    # the answer at the $SI MEDIAN there (medcol_10_yara F1=0.417, a relocated tell).
    # Straddling the answer's $SI band with these 3 signed interiors re-randomizes the
    # answer's $SI rank within the yara set without changing any row count (candidate
    # count feeds the single-pick chance band, so it must stay fixed). The band stays
    # strictly between the low bait (<=2012) and the high bait (>=2021), so the baits
    # still own the oldest/newest $SI extremes; only the INTERIOR rank is spread.
    # The over∩yara HIGH bait $SI is pushed to 2021-2023 so it stays strictly NEWER
    # than the widened interior band (top 2020) — it must keep owning the newest $SI
    # within the yara set.
    _high(True, True, "old SIGNED driver, largest gap + newest $SI/$FN in the yara set, yara-flagged; benign because validly signed",
          si_band=(2021, 2023))
    _low(True, True, "ancient SIGNED driver, smallest over-gap + oldest $SI/$FN in the yara set, yara-flagged; benign because validly signed")
    for _ in range(5):
        _interior(True, True, "SIGNED driver, $SI predates $FN from image deploy, yara-flagged; benign because signed (interior over∩yara flanker)",
                  si_band=(2014, 2019))

    # over∩unsigned group (yara-CLEAN, UNSIGNED — benign because uncorroborated). The
    # SAME round-4 straddle as over∩yara: the round-4 yara∩unsigned near-misses are
    # ALSO Unsigned (they are in BOTH the yara set AND the unsigned/notcatalog set),
    # so their recent $SI skewed the UNSIGNED set's $SI median onto the answer too
    # (medlocol_10_notcatalog F1=0.521 on a fresh band). Widen these interiors to
    # straddle the answer's 2015-2018 band (2013-2020) — re-randomizing the answer's
    # $SI rank within the unsigned set — and push the over∩unsigned high bait to
    # 2021-2023 so it keeps owning the newest $SI among unsigned rows. Row counts
    # unchanged.
    _high(False, False, "UNSIGNED file, largest gap + newest $SI/$FN among unsigned rows, NO yara; benign because uncorroborated",
          si_band=(2021, 2023))
    _low(False, False, "old UNSIGNED file, smallest over-gap + oldest $SI/$FN among unsigned rows, NO yara; benign because uncorroborated")
    for _ in range(5):
        _interior(False, False, "UNSIGNED file, $SI predates $FN from a volume op, NO yara; benign because uncorroborated (interior over∩unsigned flanker)",
                  si_band=(2014, 2019))

    # OVERALL extreme baits (yara-CLEAN, SIGNED — neither categorical leg). They own
    # the max-gap / oldest-$SI / newest-$FN OVERALL (across every row), so the
    # unrestricted argmax/oldest/newest rankings also miss the answer. The high bait's
    # $SI is pushed to 2024-2026 so it stays the newest $SI OVERALL even after the
    # over∩yara high bait moved up to 2021-2023.
    _high(False, True, "recently-imaged SIGNED driver, newest $SI/$FN + large gap overall, yara-clean; benign on both categorical legs",
          si_band=(2024, 2026))
    _low(False, True, "ancient SIGNED driver, $FN relinked by a volume op: oldest $SI/$FN + largest gap overall; signed + no yara")

    # SUB-THRESHOLD yara∩unsigned near-misses (yara-HIT, UNSIGNED, gap UNDER the
    # backdate threshold). They share the answer's TWO categorical legs but fail leg
    # A, so the yara∩unsigned 2-feature echo holds {answer + these 6} = 7 members —
    # the binding (N-1)-feature bucket -> echo F1 = 2/8 = 0.25 (below the order-2
    # floor 1/3, so the echo gate still passes; the bucket grew from 5 to 7 to make
    # the per-axis twinning below feasible — see next paragraph).
    #
    # ROUND 5 (the leak a 30-agent hunt + skeptic reproduced AND the residual the
    # round-4 fix relocated). The fundamental obstruction: the answer is the UNIQUE
    # over-threshold row, so its gap (>=1800d) dwarfs every near-miss gap (<345d).
    # gap = $FN - $SI, so a small-gap near-miss has $FN ~ $SI (within a year), while
    # the answer has $FN years AHEAD of $SI. A near-miss therefore CANNOT twin the
    # answer on BOTH absolute axes at once: a near-miss whose $FN matches the answer's
    # (recent) $FN has a recent $SI (ABOVE the answer's old $SI), and a near-miss whose
    # $SI matches the answer's (old) $SI has an old $FN (BELOW the answer's recent $FN).
    # Round 4 tried to BRACKET the answer (>=1 near-miss above + >=1 below on each
    # axis); with only 4 near-misses that hard bracket PINNED the answer's $FN rank to
    # the bucket CENTER (medcol_30_yu F1=0.54) and its $SI rank to a fixed index-1
    # (rareSIyear / median tells). A hard bracket on a tiny set is itself a position.
    #
    # THE FIX (evidence-design, generalizable): twin EACH absolute axis INDEPENDENTLY
    # with its OWN group of iid near-misses, instead of bracketing both with a shared
    # few. We split the 6 near-misses into:
    #   • 3 $FN-TWINS: target $FN drawn iid from the SAME distribution as the answer's
    #     $FN (an $SI in [2014,2019] + a [1800,3200]d gap), then $SI = $FN - small_gap.
    #     The answer is a TRUE iid member of the {answer + 3 $FN-twins} $FN population,
    #     so its $FN RANK within that 4-set is uniform — never pinned to the median or
    #     an extreme. (These 3 carry recent $SI, ABOVE the answer's, by construction.)
    #   • 3 $SI-TWINS: $SI drawn iid from the answer's $SI distribution [2014,2019],
    #     then $FN = $SI + small_gap. The answer is a TRUE iid member of the
    #     {answer + 3 $SI-twins} $SI population, so its $SI rank within that 4-set is
    #     uniform. (These 3 carry old $FN, BELOW the answer's, by construction.)
    # Net over the 7-row bucket: on $FN the answer is uniform among its 4-member
    # $FN-twin group and sits above the 3 old-$FN $SI-twins (rank uniform in the upper
    # band, median/newest single-picks ~1/4 ~ 0.25, oldest never -> 0); SYMMETRICALLY
    # on $SI. Every order statistic (newest/oldest/median/midpoint/mode/rare on $FN OR
    # $SI, restricted to the bucket) lands on the answer at most ~1/4 of seeds — below
    # the 0.40 strong-leak gate — and NONE deterministically. Every near-miss gap is
    # sub-threshold, so `argmax(gap)` within yara∩unsigned STILL uniquely picks the
    # answer (the oracle is preserved; see test_intersect_then_rank_is_the_oracle).
    # The year MODE/RARE picks are multi-pick over iid-spread years (no near-miss is
    # forced to a unique offset), so they collapse to the bucket floor, not a tell.
    def _small_gap() -> timedelta:
        return timedelta(days=rng.randint(10, BACKDATE_DAYS - 20))

    # Twin SOURCE bands. The $SI band is kept EQUAL to the answer's own [2014,2019]
    # so the near-misses do NOT perturb the GLOBAL $SI distribution (widening it spread
    # near-miss $SI into the global tails and re-pinned the answer at the global $SI
    # midpoint — midcol_10_all crept over the single-pick band). The source GAP band is
    # widened to [1200,4000]d (vs the answer's [1800,3200]) so the $FN-twins' $FN
    # STRADDLES the answer's $FN on both sides: some FN-twins land reliably newer / older
    # than any answer $FN, pulling the answer off the bucket's newest-$FN extreme. Both
    # twin types' OWN gaps stay strictly sub-threshold via _small_gap(); the source gap
    # only fixes where the target $FN sits absolutely, never the near-miss's real gap.
    # (Measured: newest_30_yu / newest-$FN-year-bucket drop to ~0.16, every yu-bucket
    # order statistic well under the 0.40 gate, and the global $SI single-picks stay at
    # the same distribution that already passed.)
    TWIN_SI = (2014, 2019)
    TWIN_GAP = (1200, 4000)

    # 3 $FN-twins: target $FN drawn from a band straddling the answer's $FN marginal;
    # $SI = $FN - small sub-threshold gap (so these carry recent $SI by construction).
    for _ in range(3):
        _t_si = _d(rng.randint(*TWIN_SI), rng.randint(1, 12), rng.randint(1, 28))
        _t_fn = _t_si + timedelta(days=rng.randint(*TWIN_GAP))
        _nm_si = _t_fn - _small_gap()
        _add(_next(), _nm_si, _t_fn, True, False,
             "yara+unsigned near-miss ($FN-twin): $FN drawn from a band straddling the "
             "answer's $FN distribution, $SI = $FN - sub-threshold gap; randomizes the "
             "answer's $FN rank within the bucket (recent $SI by construction)")
    # 3 $SI-twins: $SI drawn from a band straddling the answer's $SI marginal;
    # $FN = $SI + small sub-threshold gap (so these carry old $FN by construction).
    for _ in range(3):
        _t_si = _d(rng.randint(*TWIN_SI), rng.randint(1, 12), rng.randint(1, 28))
        _nm_fn = _t_si + _small_gap()
        _add(_next(), _t_si, _nm_fn, True, False,
             "yara+unsigned near-miss ($SI-twin): $SI drawn from a band straddling the "
             "answer's $SI distribution, $FN = $SI + sub-threshold gap; randomizes the "
             "answer's $SI rank within the bucket (old $FN by construction)")

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

    # The BINDING (N-1)-feature bucket — yara∩unsigned — is held to size 7 (answer +
    # 6 sub-threshold near-misses), so the order-2 echo floor is 2/8 = 0.25 (<= the
    # 1/3 order-2 ceiling the gate holds it to). The bucket grew from 5 to 7 so the
    # per-axis twin construction (3 $FN-twins + 3 $SI-twins) has enough iid flankers
    # on EACH axis to randomize the answer's rank instead of pinning it to the center.
    yara_unsigned = 1 + sum(1 for _nm, _p, _si, _fn, _lm, y, s, _note in decoys
                            if y and (not s))
    assert yara_unsigned == 7, f"yara∩unsigned bucket has {yara_unsigned} rows (!=7)"

    # ROUND-5 PER-AXIS TWIN invariants on the yara∩unsigned bucket. The bracket
    # invariant round 4 used (>=1 near-miss above AND below on each axis) is REMOVED:
    # on a 5-row bucket a hard two-sided bracket IS a fixed central position, which is
    # itself an order-statistic tell (medcol_30_yu F1=0.54). Instead we pin the TWIN
    # SHAPE — 6 sub-threshold near-misses split 3 $FN-twins (recent $SI by build) + 3
    # $SI-twins (old $FN by build) — and let the answer's per-axis RANK be genuinely
    # random (which the gate measures directly; it cannot be a determinism-safe assert
    # precisely because it is random). Every near-miss is sub-threshold so the oracle
    # `argmax(gap)` within the bucket still uniquely picks the answer.
    yu_nm = [(si, fn) for _nm, _p, si, fn, _lm, y, s, _note in decoys
             if y and (not s) and not is_timestomped(si, fn)]
    assert len(yu_nm) == 6, f"expected 6 sub-threshold yara∩unsigned near-misses, got {len(yu_nm)}"
    # 3 $FN-twins carry recent $SI (>= the answer's $SI, since their gap <345d dwarfed
    # by the answer's >=1800d gap pulling its $SI years older); 3 $SI-twins carry $SI
    # in the answer's [2014,2019] band. The answer's $FN is iid among the {answer +
    # $FN-twins} group and its $SI iid among the {answer + $SI-twins} group, so neither
    # axis is bracketed on BOTH sides every seed — that is the point, and the answer's
    # per-axis RANK is left genuinely random (the gate measures it; it is NOT a
    # determinism-safe invariant, so we do NOT assert a year-spread or a two-sided
    # bracket here — an iid draw can legitimately cluster a few years, and asserting
    # otherwise would crash generation on a valid seed). The mode/rare-year picks that
    # such clustering could feed are MULTI-pick and bounded at the bucket floor anyway.

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
            f"signed). {len(decoys)} decoys each defeat a 1- or 2-feature shortcut: a "
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
