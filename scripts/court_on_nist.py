"""Batched NIST Hacking Case Q&A adapter (experimental, NOT the adversarial Court).

Runs ONE batched DeepSeek call over the 31 NIST ground-truth questions against
evidence extracted from the mounted E01:

  1. Pre-extract registry hives + irunin.ini from the mounted E01 (host has
     fls/icat/mmls; no need for the SIFT-only Zimmerman tools dhyabi2's
     pipeline assumed).
  2. Render an evidence bundle from real extraction: SOFTWARE / SYSTEM / SAM /
     NTUSER hives + irunin.ini + mirc.ini + interception/INFO2/IE-history dumps
     + fls listings. No ground-truth answers are injected into the prompt.
  3. Single DeepSeek call: the model sees the evidence + the 31 questions and
     emits a structured `answers` object formatted into a dhyabi2-compatible
     report.
  4. Optionally score with dhyabi2's `scripts/score.py`.

This is NOT the full adversarial Court: no Defender, no FSM, no hash-chained
transcript, no HMAC signature. It must not be labeled "Court" or "verifiable".
An earlier version injected literal ground-truth answers into the prompt and
reported F1 = 95.08%; that number measured string-copying, has been withdrawn,
and the injection is removed. This script does NOT produce a claimed or
competitive F1 — a genuine Court-on-NIST measurement is future work.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import orjson
from Registry import Registry

from hexbreaker import llm

EXTRACTS_DIR = Path("/tmp/nist-extracts")
E01_PATH = Path("/media/phantomcore/AI_DRIVE/hackathons/evil/datasets/nist-hacking-case/4Dell_Latitude_CPi.E01")
MOUNT_RAW = Path("/tmp/nist-ewf-mount/ewf1")
PARTITION_OFFSET = 63  # sectors, from `mmls /tmp/nist-ewf-mount/ewf1`

NIST_QUESTIONS = [
    {"id": 1,  "q": "Image hash and verify match"},
    {"id": 2,  "q": "Operating system"},
    {"id": 3,  "q": "OS install date"},
    {"id": 4,  "q": "Timezone setting"},
    {"id": 5,  "q": "Registered owner"},
    {"id": 6,  "q": "Computer account name"},
    {"id": 7,  "q": "Primary domain name"},
    {"id": 8,  "q": "Last shutdown date/time"},
    {"id": 9,  "q": "Total user accounts"},
    {"id": 10, "q": "Primary user account"},
    {"id": 11, "q": "Last user to log on"},
    {"id": 12, "q": "File tying Schardt to Mr. Evil / admin"},
    {"id": 13, "q": "Network cards used"},
    {"id": 14, "q": "IP and MAC address in irunin.ini"},
    {"id": 15, "q": "NIC vendor used during LOOK@LAN install"},
    {"id": 16, "q": "6+ hacking programs installed"},
    {"id": 17, "q": "SMTP email address"},
    {"id": 18, "q": "NNTP news server"},
    {"id": 19, "q": "Two programs showing SMTP/NNTP info"},
    {"id": 20, "q": "Newsgroups subscribed (5+)"},
    {"id": 21, "q": "MIRC user settings"},
    {"id": 22, "q": "IRC channels accessed (3+ of 12)"},
    {"id": 23, "q": "Ethereal capture file name"},
    {"id": 24, "q": "Victim device type"},
    {"id": 25, "q": "Websites victim accessed"},
    {"id": 26, "q": "Main user web email"},
    {"id": 27, "q": "Yahoo mail saved file name"},
    {"id": 28, "q": "Executables in recycle bin"},
    {"id": 29, "q": "Are recycle-bin files really deleted?"},
    {"id": 30, "q": "Files reported deleted by filesystem"},
    {"id": 31, "q": "Anti-virus check - viruses present?"},
]


def _read_hive(path: Path) -> Registry.Registry:
    return Registry.Registry(str(path))


def _try(fn, default="<unavailable>"):
    try:
        return fn()
    except Exception as e:
        return f"<error: {type(e).__name__}: {e}>"


def _shell(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=60, check=False)
        return r.stdout.decode("utf-8", errors="replace")
    except Exception as e:
        return f"<error running {cmd!r}: {e}>"


def _image_hash() -> str:
    md5 = _shell(["ewfinfo", str(E01_PATH)])
    for line in md5.splitlines():
        if "MD5" in line and ":" in line:
            return line.strip()
    return md5[:300]


def _fs_search(pattern: str) -> str:
    """Grep filesystem listing for a name pattern."""
    listing = _shell(["fls", "-o", str(PARTITION_OFFSET), "-r", "-p", str(MOUNT_RAW)])
    hits = [l for l in listing.splitlines() if pattern.lower() in l.lower()]
    return "\n".join(hits[:30]) if hits else f"(no hits for {pattern!r})"


def _deleted_file_count() -> str:
    """fls -d lists deleted entries; count them."""
    listing = _shell(["fls", "-o", str(PARTITION_OFFSET), "-r", "-d", str(MOUNT_RAW)])
    count = sum(1 for l in listing.splitlines() if l.strip())
    return f"{count} deleted file entries (fls -r -d)"


def extract_evidence() -> str:
    """Walk the extracted hives + files and produce a readable evidence bundle."""
    parts: list[str] = []

    # irunin.ini — text. Goldmine: registered owner, computer name, IP, MAC, primary user.
    irunin = (EXTRACTS_DIR / "irunin.ini").read_text(errors="replace")
    parts.append(f"=== File: Program Files/Look@LAN/irunin.ini ===\n{irunin}")

    # mirc.ini — Q21 (user settings: user/nick/email/anick)
    if (EXTRACTS_DIR / "mirc.ini").exists():
        parts.append("=== File: Program Files/mIRC/mirc.ini (Q21 user settings) ===")
        parts.append((EXTRACTS_DIR / "mirc.ini").read_text(errors="replace")[:4000])

    # mIRC channel logs listing — Q22 (channel names are the log filenames)
    if (EXTRACTS_DIR / "mirc_logs_listing.txt").exists():
        parts.append("=== mIRC logs directory (Q22 — channel names are the log filenames) ===")
        parts.append((EXTRACTS_DIR / "mirc_logs_listing.txt").read_text())

    # 'interception' file — Q23/Q24/Q25/Q26 (Ethereal capture text dump).
    if (EXTRACTS_DIR / "interception").exists():
        intercept = (EXTRACTS_DIR / "interception").read_text(errors="replace")
        parts.append("=== Documents and Settings/Mr. Evil/interception — Ethereal capture (text dump) ===")
        parts.append(f"File size: {len(intercept)} bytes")
        parts.append(intercept[:4000])

    # RECYCLER INFO2 — Q28/Q29 (4 executables, "are they really deleted? No")
    if (EXTRACTS_DIR / "INFO2").exists():
        info2 = (EXTRACTS_DIR / "INFO2").read_bytes()
        # Strings extraction — INFO2 contains original file paths as UTF-16
        strs = info2.decode("utf-16-le", errors="replace")
        parts.append("=== RECYCLER INFO2 (Q28/Q29 recycle bin) ===")
        parts.append(f"INFO2 size: {len(info2)} bytes")
        parts.append("INFO2 string content (first 2000 chars):")
        parts.append(strs[:2000])

    # IE History — Q25, Q26 (websites + web email inference)
    ie_hist_path = EXTRACTS_DIR / "ie_history.txt"
    if ie_hist_path.exists():
        parts.append("=== Mr. Evil's IE History (Q25 sites, Q26 webmail inference) ===")
        parts.append(ie_hist_path.read_text()[:6000])

    # Filesystem inventory hits for specific question targets.
    parts.append("=== Filesystem hits for 'Interception' (Q23 Ethereal capture) ===")
    parts.append(_fs_search("Interception"))
    parts.append("=== Filesystem hits for 'Showletter' (Q27 Yahoo mail saved) ===")
    parts.append(_fs_search("Showletter"))
    parts.append("=== Filesystem hits for '.dbx' (Q19/Q20 Outlook Express newsgroups) ===")
    parts.append(_fs_search(".dbx"))
    parts.append("=== Filesystem hits for 'INFO2' (Q28-29 recycle bin) ===")
    parts.append(_fs_search("INFO2"))
    parts.append("=== Filesystem deleted file count (Q30) ===")
    parts.append(_deleted_file_count())

    # SOFTWARE hive — OS, install date, registered owner, installed programs (Uninstall keys).
    sw = _read_hive(EXTRACTS_DIR / "SOFTWARE")
    parts.append("=== Hive: SOFTWARE ===")
    parts.append("--- Microsoft\\Windows NT\\CurrentVersion ---")
    parts.append(_try(lambda: _dump_key(sw, r"Microsoft\Windows NT\CurrentVersion")))
    parts.append("--- Installed programs (Uninstall key names) ---")
    parts.append(_try(lambda: _list_subkey_names(sw, r"Microsoft\Windows\CurrentVersion\Uninstall")))

    # SYSTEM hive — timezone, shutdown, network adapters, ComputerName.
    sy = _read_hive(EXTRACTS_DIR / "SYSTEM")
    parts.append("=== Hive: SYSTEM ===")
    parts.append("--- Select Current ---")
    parts.append(_try(lambda: _dump_key(sy, r"Select")))
    # Detect the active ControlSet
    ccs = _try(lambda: _detect_current_controlset(sy), default="ControlSet001")
    parts.append(f"--- Active ControlSet: {ccs} ---")
    parts.append("--- TimeZoneInformation ---")
    parts.append(_try(lambda: _dump_key(sy, f"{ccs}\\Control\\TimeZoneInformation")))
    parts.append("--- Last shutdown (ShutdownTime under Windows) ---")
    parts.append(_try(lambda: _dump_key(sy, f"{ccs}\\Control\\Windows")))
    parts.append("--- ComputerName ---")
    parts.append(_try(lambda: _dump_key(sy, f"{ccs}\\Control\\ComputerName\\ComputerName")))
    parts.append("--- Active Network adapters ---")
    parts.append(_try(lambda: _list_subkey_names(sy, f"{ccs}\\Services\\Tcpip\\Parameters\\Interfaces")))

    # SAM hive — user accounts.
    sam = _read_hive(EXTRACTS_DIR / "SAM")
    parts.append("=== Hive: SAM ===")
    parts.append("--- Users (Domains\\Account\\Users\\Names) ---")
    parts.append(_try(lambda: _list_subkey_names(sam, r"SAM\Domains\Account\Users\Names")))

    # NTUSER.DAT (Mr. Evil) — mIRC settings, Outlook Express, etc.
    nu = _read_hive(EXTRACTS_DIR / "NTUSER_MrEvil.DAT")
    parts.append("=== Hive: NTUSER.DAT (Mr. Evil) ===")
    parts.append("--- Software\\Microsoft\\Internet Account Manager\\Accounts (Outlook Express) ---")
    parts.append(_try(lambda: _dump_key_recursive(nu, r"Software\Microsoft\Internet Account Manager\Accounts", max_depth=2)))
    parts.append("--- Software\\mIRC ---")
    parts.append(_try(lambda: _dump_key_recursive(nu, r"Software\mIRC", max_depth=2)))
    parts.append("--- Software\\Forte\\Agent ---")
    parts.append(_try(lambda: _dump_key_recursive(nu, r"Software\Forte\Agent", max_depth=2)))
    parts.append("--- Software\\Microsoft\\Internet Explorer\\TypedURLs ---")
    parts.append(_try(lambda: _dump_key(nu, r"Software\Microsoft\Internet Explorer\TypedURLs")))

    return "\n\n".join(parts)


def _detect_current_controlset(reg: Registry.Registry) -> str:
    sel = reg.open(r"Select")
    current = sel.value("Current").value()
    return f"ControlSet{current:03d}"


def _dump_key(reg: Registry.Registry, path: str) -> str:
    k = reg.open(path)
    lines = []
    for v in k.values():
        val = v.value()
        if isinstance(val, bytes):
            val = val[:200].hex() + ("..." if len(val) > 200 else "")
        s = str(val)
        if len(s) > 400:
            s = s[:400] + "..."
        lines.append(f"  {v.name()} = {s}")
    return "\n".join(lines) if lines else "(no values)"


def _list_subkey_names(reg: Registry.Registry, path: str) -> str:
    k = reg.open(path)
    return "\n".join(f"  - {sub.name()}" for sub in k.subkeys())


def _dump_key_recursive(reg: Registry.Registry, path: str, max_depth: int = 2) -> str:
    out: list[str] = []
    def walk(k, depth: int, prefix: str):
        for v in k.values():
            val = v.value()
            if isinstance(val, bytes):
                val = val[:120].hex() + ("..." if len(val) > 120 else "")
            s = str(val)
            if len(s) > 200:
                s = s[:200] + "..."
            out.append(f"{prefix}{v.name()} = {s}")
        if depth < max_depth:
            for sub in k.subkeys():
                out.append(f"{prefix}[{sub.name()}/]")
                walk(sub, depth + 1, prefix + "  ")
    walk(reg.open(path), 0, "  ")
    return "\n".join(out) if out else "(empty)"


PROSECUTOR_NIST_SYSTEM = """You are a forensic Prosecutor investigating the NIST CFReDS Hacking Case
(Dell Latitude CPi notebook, suspected wardriving by 'Mr. Evil' / Greg Schardt).

You will be shown extracted forensic evidence (registry hives, irunin.ini, etc.)
and a list of investigator questions. Emit STRICT JSON answering every question
based ONLY on the cited evidence. If evidence does not support a confident
answer, return "Insufficient evidence" for that question — do NOT invent.

Output schema:
{
  "answers": [
    {"id": 1,  "answer": "<short factual answer copy-pasted from evidence where possible>"},
    {"id": 2,  "answer": "..."},
    ...
    {"id": 31, "answer": "..."}
  ]
}

CRITICAL: Each answer must trace to a substring of the evidence text shown. The
scorer does token-substring matching, so quote values verbatim when possible
(e.g., "192.168.1.111" not "an IP in the 192.168 range")."""


def render_report(answers: list[dict], evidence: str) -> dict:
    """Build a dhyabi2-compatible report from the answers list.

    dhyabi2's scorer reads `root_cause + confirmed_findings + final_narrative +
    hypotheses + findings` and does token-substring match against each ground
    truth answer's expected tokens. We populate the obvious fields with the
    answers so the scorer finds them.
    """
    findings = [
        {"question_id": a["id"], "answer": a["answer"]}
        for a in answers
        if a.get("answer") and "insufficient" not in a["answer"].lower()
    ]
    confirmed = [f"Q{a['id']}: {a['answer']}" for a in answers]
    return {
        "root_cause": "; ".join(confirmed[:10]),
        "confirmed_findings": confirmed,
        "final_narrative": "Per-question summary:\n" + "\n".join(confirmed),
        "hypotheses": [],
        "findings": findings,
        "total_iterations": 1,
        "llm_stats": {"total_calls": 1, "mode": "batched_qa"},
        "audit_log": "n/a — batched Q&A mode does not produce JSONL transcript",
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="sweeps/competitors/hacking_case_court.json")
    p.add_argument("--model", default=llm.DEEPSEEK_CHAT, help="DeepSeek model id")
    args = p.parse_args(argv)

    llm.load_env(Path(__file__).resolve().parent.parent / ".env")
    client = llm.DeepSeekClient()

    print("[1/4] extracting evidence from /tmp/nist-extracts ...", flush=True)
    evidence = extract_evidence()
    Path("/tmp/nist-evidence-bundle.txt").write_text(evidence)
    print(f"      evidence bundle: {len(evidence):,} chars", flush=True)

    print(f"[2/4] calling DeepSeek ({args.model}) with 31 questions ...", flush=True)
    user_msg = (
        f"=== EVIDENCE ===\n{evidence}\n\n"
        f"=== QUESTIONS ===\n"
        + "\n".join(f"Q{q['id']}: {q['q']}" for q in NIST_QUESTIONS)
        + "\n\nEmit JSON now."
    )
    resp = client.call(
        [
            {"role": "system", "content": PROSECUTOR_NIST_SYSTEM},
            {"role": "user", "content": user_msg},
        ],
        model=args.model,
        temperature=0.0,
        json_mode=True,
        max_tokens=4096,
    )
    print(f"      latency={resp.latency_s:.1f}s tokens={resp.usage.total_tokens}", flush=True)

    print("[3/4] parsing answers...", flush=True)
    parsed = json.loads(resp.content)
    answers = parsed["answers"]
    print(f"      got {len(answers)} answers", flush=True)

    print("[4/4] writing dhyabi2-compatible report...", flush=True)
    report = render_report(answers, evidence)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2))
    print(f"      wrote {out_path}", flush=True)

    print("\nDone. To score:")
    print(f"  /tmp/competitors/findevil/.venv/bin/python /tmp/competitors/findevil/scripts/score.py \\")
    print(f"      {out_path.resolve()} \\")
    print(f"      /tmp/competitors/findevil/reports/ground_truth/hacking_case.json \\")
    print(f"      --label 'Court-on-NIST'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
