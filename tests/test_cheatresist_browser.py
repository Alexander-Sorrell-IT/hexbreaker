"""Cheat-resistance gate for the browser Forge template (Option 1, reasoning-only).

The defining property we enforce: the malicious URL is solvable ONLY by the
intended forensic reasoning, never by a surface shortcut. Concretely, every
candidate URL is drawn from ONE neutral lexical pool, and maliciousness is encoded
purely in the navigation semantics that log2timeline's web-history parser records:

    exec      — the visit landed on an executable download,
    redirect  — it was reached via a CLIENT/SERVER_REDIRECT qualifier,
    untrusted — the referring (from_visit) host is an off-site host that never
                appears as its own logged visit.

The evil URL is the unique row satisfying exec AND redirect AND untrusted. The
redirect and untrusted bits are each set on the PLURALITY (5 of 7) of rows, so the
evil VALUE of those tells is the plurality — never unique, never rare. The exec
bit is the minority (3 of 7) but is NOT surface-detectable (extensions are
format-identical across classes), so no rarity/frequency op can exploit it. That
is the load-bearing mechanism: rarity / uniqueness / anomaly heuristics (the only
tools a no-domain-knowledge cheater has) cannot isolate the answer. Only the
semantic triple conjunction isolates the evil row.

The decoy bit-set carries FOUR (0,1,1) siblings, so the redirect-AND-untrusted
residue — the only two-tell sub-conjunction a no-domain cheater can narrow to by
stacking the author-blessed frequency + membership ops (it cannot isolate the
exec class, whose surface form is format-identical across classes) — lands on
FIVE rows (evil + the four siblings flipping the omitted exec tell), not a clean
pair. A coin-flip over the residue tops out at ~1/5, and the omitted exec tell's
RAW surface realization fires on the sibling decoys too: the benign extensions are
format-identical 4-char lowercase strings (assigned uniquely within each class so
none is modal), every URL is padded to a constant length, and the scheme is
constant, so no extension/length/scheme pick peels the answer off the residue.
This closes the sub-conjunction shortcut a prior hunter exploited.

Two deterministic, no-LLM baselines, measured over K fresh seeds:

  CHEATER suite — strategies with NO domain knowledge. It may use raw lexical /
    positional / frequency / membership / format features ONLY. It may NOT compute
    the three forensic predicates (executable-extension CLASS, redirect-qualifier,
    untrusted-referrer) and AND/sum them — those ARE the domain knowledge the
    oracle owns; a cheater that computes them is the oracle in a costume and would
    trivially score ~1.0 (the evil row is the unique max-popcount row of any
    single-evil 3-bit AND). We deliberately exclude that. We take the cheater's
    BEST mean-F1 across all strategies.

  ORACLE — encodes the INTENDED forensic rule: pick the row that satisfies the
    exec AND redirect AND untrusted-referrer conjunction. Must score ~1.0 (proves
    the case is solvable-by-reasoning and the answer key is correct).

GATE: cheater_best_f1 <= ~0.3 (chance ~= 1/7 ~= 0.143; headroom for K-luck) AND
oracle_f1 >= 0.9 AND gap = oracle_f1 - cheater_best_f1 >= 0.6, over K >= 12 seeds.

The cheater reads ONLY what a submitter sees: manifest.json + mock_outputs/. It
NEVER reads answer_key.json (that is the ground truth, withheld for scoring).
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter
from pathlib import Path

from hexbreaker.forge import template_browser
from hexbreaker.forge.case import load_case

# K fresh seeds. >=12 per the gate; we use a spread of arbitrary seeds so a lucky
# single draw cannot mask a leak.
_SEEDS = [1, 2, 3, 7, 11, 19, 23, 31, 101, 4729, 8821, 31337, 55555, 90210]

_URL_RE = re.compile(r"https?://[^/\s]+")
_EXEC_EXTS = (".exe", ".msi", ".scr", ".hta")


# --------------------------------------------------------------------------- #
# Evidence parsing — exactly what a submitter can read off disk.
# --------------------------------------------------------------------------- #


def _gen(seed: int, out_dir: Path, *, provocateur: bool) -> tuple[list[str], list[dict], str]:
    """Generate a case and return (be_urls, l2t_rows, evil_url).

    be_urls  — URLs carved by bulk_extractor (the disk primary), in file order.
    l2t_rows — log2timeline web-history rows as dicts (incl. transition/from_visit).
    evil_url — the ground-truth target (read from answer_key ONLY for scoring,
               never exposed to the cheater).
    """
    template_browser.generate(seed=seed, out_dir=out_dir, provocateur=provocateur)
    _, answer = load_case(out_dir)
    evil_url = answer.expected_findings[0].target

    be_text = (out_dir / "mock_outputs" / "bulk_extractor_url.txt").read_text()
    be_urls: list[str] = []
    for line in be_text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        # offset \t url \t context
        be_urls.append(line.split("\t", 2)[1])

    l2t_text = (out_dir / "mock_outputs" / "l2t_webhist.csv").read_text()
    l2t_rows = list(csv.DictReader(io.StringIO(l2t_text)))

    return be_urls, l2t_rows, evil_url


def _host(url: str) -> str:
    m = _URL_RE.match(url)
    return m.group(0).split("//", 1)[1] if m else ""


def _ext(url: str) -> str:
    tail = url.rsplit("/", 1)[-1]
    return ("." + tail.rsplit(".", 1)[-1]) if "." in tail else ""


def _tld(url: str) -> str:
    h = _host(url)
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", h):  # raw IP — no TLD
        return ""
    return h.rsplit(".", 1)[-1] if "." in h else ""


# --------------------------------------------------------------------------- #
# CHEATER strategies. Each returns ONE url (its single guess) or None.
# NO domain knowledge: raw lexical / positional / frequency / membership /
# format features only. None of these may compute the exec/redirect/untrusted
# forensic predicates as the discriminator — that boundary is what keeps the
# measured gap honest.
# --------------------------------------------------------------------------- #


def _rarest_by(urls: list[str], key) -> str | None:
    """Pick the url whose key-value is the (uniquely) rarest. None on a tie."""
    counts = Counter(key(u) for u in urls)
    ranked = sorted(set(urls), key=lambda u: (counts[key(u)], u))
    if not ranked:
        return None
    if len(ranked) > 1 and counts[key(ranked[0])] == counts[key(ranked[1])]:
        return None  # ambiguous rarest — strategy declines
    return ranked[0]


def _modal_by(urls: list[str], key) -> str | None:
    """Pick a url whose key-value is the modal (most common) value."""
    counts = Counter(key(u) for u in urls)
    if not counts:
        return None
    modal_val, _ = counts.most_common(1)[0]
    for u in urls:
        if key(u) == modal_val:
            return u
    return None


def _unique_by(urls: list[str], key) -> str | None:
    """If exactly one url has a value no other url shares, pick it."""
    counts = Counter(key(u) for u in urls)
    singles = [u for u in urls if counts[key(u)] == 1]
    return singles[0] if len(singles) == 1 else None


def _cheater_strategies(be_urls: list[str], l2t_rows: list[dict]) -> dict[str, str | None]:
    """All no-domain-knowledge single-pick strategies -> their guessed url."""
    l2t_urls = [r["url"] for r in l2t_rows]
    url_set = set(l2t_urls) | set(be_urls)
    out: dict[str, str | None] = {}

    # --- position / label-file order ---
    out["be_first_row"] = be_urls[0] if be_urls else None
    out["be_last_row"] = be_urls[-1] if be_urls else None
    out["l2t_first_row"] = l2t_urls[0] if l2t_urls else None
    out["l2t_last_row"] = l2t_urls[-1] if l2t_urls else None

    # --- format oddity ---
    out["longest_url"] = max(be_urls, key=len) if be_urls else None
    out["shortest_url"] = min(be_urls, key=len) if be_urls else None
    out["most_path_segments"] = (
        max(be_urls, key=lambda u: u.count("/")) if be_urls else None
    )
    raw_ips = [u for u in be_urls if re.match(r"^\d", _host(u))]
    out["raw_ip_host"] = raw_ips[0] if len(raw_ips) == 1 else None
    non_ascii = [u for u in be_urls if any(ord(ch) > 127 for ch in u)]
    out["non_ascii_url"] = non_ascii[0] if len(non_ascii) == 1 else None

    # --- rarity (minority value) across raw columns ---
    out["rarest_extension"] = _rarest_by(be_urls, _ext)
    out["rarest_tld"] = _rarest_by(be_urls, _tld)
    out["rarest_host"] = _rarest_by(be_urls, _host)
    out["rarest_scheme"] = _rarest_by(be_urls, lambda u: u.split("://", 1)[0])
    out["rarest_transition"] = _pick_from_rows(l2t_rows, l2t_urls, "transition", rarest=True)
    out["rarest_referrer"] = _pick_from_rows(l2t_rows, l2t_urls, "from_visit", rarest=True)

    # --- frequency (modal value match) ---
    out["modal_extension"] = _modal_by(be_urls, _ext)
    out["modal_transition"] = _pick_from_rows(l2t_rows, l2t_urls, "transition", rarest=False)
    out["modal_referrer"] = _pick_from_rows(l2t_rows, l2t_urls, "from_visit", rarest=False)

    # --- uniqueness (the only row with a non-shared column value) ---
    out["unique_extension"] = _unique_by(be_urls, _ext)
    out["unique_transition"] = _unique_col(l2t_rows, "transition")
    out["unique_referrer"] = _unique_col(l2t_rows, "from_visit")

    # --- membership (pure string test, no domain knowledge) ---
    # The from_visit value whose host is not itself a logged visit. This is the
    # RAW form of the "untrusted" signal; the RARITY/minority pick of it must land
    # benign (untrusted is the 5/7 majority, so its minority is the trusted rows).
    logged_hosts = {_host(u) for u in l2t_urls}
    off_site = [
        r["url"] for r in l2t_rows
        if r["from_visit"] and _host(r["from_visit"]) not in logged_hosts
    ]
    # Minority/rarest membership pick: the row whose membership class is rarer.
    in_site = [r["url"] for r in l2t_rows if r["url"] not in off_site]
    minority = off_site if len(off_site) < len(in_site) else in_site
    out["membership_minority"] = minority[0] if len(minority) == 1 else None

    # --- absent-from-L2T (this isolates the plant, which must be REJECTED) ---
    absent = [u for u in be_urls if u not in set(l2t_urls)]
    out["absent_from_l2t"] = absent[0] if len(absent) == 1 else None

    # --- aggregate oddity: the row with the most non-modal field values across
    # the raw structural columns (a generic anomaly scorer, still no domain
    # knowledge of WHICH value is malicious). ---
    out["most_nonmodal_fields"] = _most_nonmodal(l2t_rows)

    # --- THE SUB-CONJUNCTION ATTACK (the leak a prior hunter exploited). ---
    # A no-domain cheater can stack TWO author-blessed ops — a FREQUENCY op on the
    # transition string (a proxy for "redirect") and the MEMBERSHIP op above
    # (off-site referrer, a proxy for "untrusted") — to narrow to a small residue
    # WITHOUT ever computing the forensic predicates, then try to peel the answer off
    # that residue with a RAW lexical/positional feature. None of these compute the
    # exec/redirect/untrusted CLASSES (no curated exec list, no "REDIRECT" substring
    # test) — they are pure frequency + membership + format ops, exactly the
    # cheater's toolbox. We try BOTH frequency narrowings (the rows that MATCH the
    # modal transition and the rows that do NOT), so whichever string is modal the
    # gate measures the attack that actually contains evil. The template must make
    # the evil-containing residue large AND inseparable by any raw feature.
    off_set = set(off_site)
    modal_t = Counter(r["transition"] for r in l2t_rows).most_common(1)[0][0] if l2t_rows else None
    for tag, want_modal in (("modal", True), ("nonmodal", False)):
        trans_group = {
            r["url"] for r in l2t_rows if (r["transition"] == modal_t) == want_modal
        }
        residue = sorted(u for u in trans_group if u in off_set)
        # (a) coin-flip floor: commit to the first row of the narrowed residue.
        out[f"subconj_{tag}_first"] = residue[0] if residue else None
        # (b) raw extension-length tiebreak within the residue (the prior 0.875 cheat).
        ext4 = [u for u in residue if len(_ext(u)) == 4]
        out[f"subconj_{tag}_extlen4"] = ext4[0] if len(ext4) == 1 else None
        # (c) longest / shortest URL within the residue (format oddity in the pair).
        out[f"subconj_{tag}_longest"] = max(residue, key=len) if residue else None
        out[f"subconj_{tag}_shortest"] = min(residue, key=len) if residue else None

    _ = url_set  # retained for clarity; membership already used above
    return out


def _pick_from_rows(
    rows: list[dict], urls: list[str], col: str, *, rarest: bool
) -> str | None:
    counts = Counter(r[col] for r in rows)
    if not counts:
        return None
    if rarest:
        ranked = sorted(rows, key=lambda r: (counts[r[col]], r["url"]))
        if len(ranked) > 1 and counts[ranked[0][col]] == counts[ranked[1][col]]:
            return None
        return ranked[0]["url"]
    modal_val, _ = counts.most_common(1)[0]
    for r in rows:
        if r[col] == modal_val:
            return r["url"]
    return None


def _unique_col(rows: list[dict], col: str) -> str | None:
    counts = Counter(r[col] for r in rows)
    singles = [r["url"] for r in rows if counts[r[col]] == 1]
    return singles[0] if len(singles) == 1 else None


def _most_nonmodal(rows: list[dict]) -> str | None:
    cols = ["transition", "from_visit"]
    modal = {c: Counter(r[c] for r in rows).most_common(1)[0][0] for c in cols}
    scored = sorted(
        rows, key=lambda r: (-sum(r[c] != modal[c] for c in cols), r["url"])
    )
    if not scored:
        return None
    if len(scored) > 1:
        top = sum(scored[0][c] != modal[c] for c in cols)
        second = sum(scored[1][c] != modal[c] for c in cols)
        if top == second:
            return None  # ambiguous — decline
    return scored[0]["url"]


# --------------------------------------------------------------------------- #
# ORACLE — the intended forensic rule (the only component allowed the semantics).
# --------------------------------------------------------------------------- #


def _oracle(l2t_rows: list[dict]) -> str | None:
    """Pick the unique row satisfying exec AND redirect AND untrusted-referrer."""
    logged_hosts = {_host(r["url"]) for r in l2t_rows}
    hits = []
    for r in l2t_rows:
        is_exec = r["url"].endswith(_EXEC_EXTS)
        is_redirect = "REDIRECT" in r["transition"]
        ref = r["from_visit"]
        is_untrusted = bool(ref) and _host(ref) not in logged_hosts
        if is_exec and is_redirect and is_untrusted:
            hits.append(r["url"])
    return hits[0] if len(hits) == 1 else None


# --------------------------------------------------------------------------- #
# Scoring — single expected finding, so per-seed F1 is 1.0 iff guess == evil.
# --------------------------------------------------------------------------- #


def _f1(guess: str | None, evil: str) -> float:
    return 1.0 if guess == evil else 0.0


def _measure(provocateur: bool, tmp_path: Path) -> tuple[dict[str, float], float]:
    """Return (cheater_strategy -> mean F1, oracle mean F1) over _SEEDS."""
    strat_scores: dict[str, list[float]] = {}
    oracle_scores: list[float] = []
    for seed in _SEEDS:
        cd = tmp_path / f"case-{seed}-{int(provocateur)}"
        be_urls, l2t_rows, evil = _gen(seed, cd, provocateur=provocateur)
        for name, guess in _cheater_strategies(be_urls, l2t_rows).items():
            strat_scores.setdefault(name, []).append(_f1(guess, evil))
        oracle_scores.append(_f1(_oracle(l2t_rows), evil))
    cheater = {name: sum(v) / len(v) for name, v in strat_scores.items()}
    oracle = sum(oracle_scores) / len(oracle_scores)
    return cheater, oracle


# --------------------------------------------------------------------------- #
# Tests / the numeric gate.
# --------------------------------------------------------------------------- #


def test_cheater_best_f1_at_or_below_chance(tmp_path: Path) -> None:
    """No no-domain-knowledge strategy beats ~chance. Reports the peak strategy."""
    cheater, _oracle_f1 = _measure(provocateur=True, tmp_path=tmp_path)
    best_name = max(cheater, key=cheater.get)
    best = cheater[best_name]
    assert best <= 0.3 + 1e-9, (
        f"cheater strategy {best_name!r} scored mean F1={best:.3f} (> 0.3) over "
        f"{len(_SEEDS)} seeds — a surface shortcut isolates the answer. "
        f"Full table: {dict(sorted(cheater.items(), key=lambda kv: -kv[1]))}"
    )


def test_oracle_solves_the_case(tmp_path: Path) -> None:
    """The intended forensic conjunction scores ~1.0 — case is solvable + key OK."""
    _cheater, oracle = _measure(provocateur=True, tmp_path=tmp_path)
    assert oracle >= 0.9, f"oracle mean F1={oracle:.3f} (< 0.9) — case not solvable by the rule"


def test_gap_meets_gate(tmp_path: Path) -> None:
    """oracle - cheater_best >= 0.6, the headline cheat-resistance gate."""
    cheater, oracle = _measure(provocateur=True, tmp_path=tmp_path)
    cheater_best = max(cheater.values())
    gap = oracle - cheater_best
    assert oracle >= 0.9, f"oracle F1={oracle:.3f} < 0.9"
    assert cheater_best <= 0.3 + 1e-9, f"cheater_best F1={cheater_best:.3f} > 0.3"
    assert gap >= 0.6, (
        f"gap={gap:.3f} < 0.6 (oracle={oracle:.3f}, cheater_best={cheater_best:.3f})"
    )


def test_gate_holds_without_provocateur_too(tmp_path: Path) -> None:
    """The gate must also hold for the non-provocateur case (no plant present)."""
    cheater, oracle = _measure(provocateur=False, tmp_path=tmp_path)
    cheater_best = max(cheater.values())
    assert oracle >= 0.9
    assert cheater_best <= 0.3 + 1e-9, (
        f"cheater_best={cheater_best:.3f}; "
        f"table={dict(sorted(cheater.items(), key=lambda kv: -kv[1]))}"
    )
    assert oracle - cheater_best >= 0.6


def test_membership_minority_pick_lands_benign(tmp_path: Path) -> None:
    """Explicit diversity check #1 (advisor): the rarity/minority pick of the raw
    untrusted-referrer membership signal must NOT isolate evil — untrusted is the
    4/7 majority, so its minority is the benign (trusted) rows."""
    hits = 0
    for seed in _SEEDS:
        cd = tmp_path / f"mem-{seed}"
        be_urls, l2t_rows, evil = _gen(seed, cd, provocateur=False)
        guess = _cheater_strategies(be_urls, l2t_rows)["membership_minority"]
        if guess == evil:
            hits += 1
    assert hits / len(_SEEDS) <= 0.3 + 1e-9, (
        f"membership_minority hit evil {hits}/{len(_SEEDS)} times — untrusted "
        f"signal is rarity-recoverable; dilute it"
    )


def test_modal_transition_does_not_isolate_evil(tmp_path: Path) -> None:
    """Explicit diversity check #2 (advisor): 'matches modal transition string'
    must not preferentially land on evil. The modal transition is now the MAJORITY
    redirect string (count 3, carried only by decoys), so this cheat never even
    points at the evil row."""
    hits = 0
    for seed in _SEEDS:
        cd = tmp_path / f"mt-{seed}"
        be_urls, l2t_rows, evil = _gen(seed, cd, provocateur=False)
        guess = _cheater_strategies(be_urls, l2t_rows)["modal_transition"]
        if guess == evil:
            hits += 1
    assert hits / len(_SEEDS) <= 0.3 + 1e-9, (
        f"modal_transition hit evil {hits}/{len(_SEEDS)} times"
    )


def test_subconjunction_attack_does_not_isolate_evil(tmp_path: Path) -> None:
    """Explicit regression for the hunter's leak: narrowing by [non-modal
    transition] AND [off-site referrer] (two author-blessed no-domain ops), then
    peeling the residue with a raw lexical/positional feature, must NOT recover the
    answer. The residue is >=3 rows and format-inseparable, so every such pick
    stays at or below ~chance."""
    names = [
        f"subconj_{tag}_{pick}"
        for tag in ("modal", "nonmodal")
        for pick in ("first", "extlen4", "longest", "shortest")
    ]
    hits = {name: 0 for name in names}
    for seed in _SEEDS:
        cd = tmp_path / f"sc-{seed}"
        be_urls, l2t_rows, evil = _gen(seed, cd, provocateur=False)
        strats = _cheater_strategies(be_urls, l2t_rows)
        for name in names:
            if strats[name] == evil:
                hits[name] += 1
    for name in names:
        assert hits[name] / len(_SEEDS) <= 0.3 + 1e-9, (
            f"sub-conjunction strategy {name!r} hit evil {hits[name]}/{len(_SEEDS)} "
            f"times — the redirect-AND-untrusted residue is peelable by a raw feature"
        )
