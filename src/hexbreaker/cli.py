"""Hexbreaker CLI entry point. Subcommands wired in as each subsystem lands."""

from __future__ import annotations

from pathlib import Path

import click
import orjson

from .court.hmac_chain import sign_transcript, verify_signature
from .forge import template_registry_persistence, template_timestomp
from .forge.case import AnswerKey
from .runner.court_runner import run_court_on_case
from .scorer.exact_match import score
from .transcript import verify

TEMPLATES = {
    "timestomp": template_timestomp.generate,
    "registry_persistence": template_registry_persistence.generate,
}


@click.group()
@click.version_option()
def main() -> None:
    """Hexbreaker — adversarial DFIR triage and benchmark."""


@main.command()
@click.option("--seed", type=int, required=True, help="Case generation seed.")
@click.option(
    "--template",
    default="timestomp",
    type=click.Choice(sorted(TEMPLATES.keys())),
    help="Case template id.",
)
@click.option("--out", type=click.Path(), required=True, help="Output case directory.")
@click.option(
    "--provocateur/--no-provocateur",
    default=False,
    help="Inject planted-evidence payloads. Robust agents must NOT confirm them.",
)
def generate(seed: int, template: str, out: str, provocateur: bool) -> None:
    """Generate a synthetic DFIR case from a seed."""
    manifest = TEMPLATES[template](seed, out, provocateur=provocateur)
    click.echo(f"generated case {manifest.case_id} at {out}")
    click.echo(f"  template: {manifest.template}")
    click.echo(f"  provocateur: {provocateur}")
    click.echo(f"  pre_pass_steps: {len(manifest.pre_pass_steps)}")
    click.echo(f"  defender_steps: {len(manifest.defender_steps)}")
    click.echo(f"  mock_outputs: {len(manifest.mock_outputs)}")


@main.command()
@click.option("--agent", required=True, help="Agent id: court | dhyabi2 | marez8505 | valhuntir | sift")
@click.option("--case", type=click.Path(exists=True), required=True, help="Case directory.")
@click.option("--out", type=click.Path(), required=True, help="Findings output path.")
def run(agent: str, case: str, out: str) -> None:
    """Run an agent on a case and capture findings."""
    if agent != "court":
        raise click.UsageError(f"agent {agent!r} not implemented yet — only 'court' lands on 5/29")
    result = run_court_on_case(case, out)
    click.echo(f"court run finished: {result.case_id}")
    click.echo(f"  transcript: {result.transcript_path}")
    click.echo(f"  findings: {len(result.findings)} → {result.findings_path}")
    for f in result.findings:
        click.echo(f"    - {f['artifact_kind']} target={f['target']!r} verdict={f['verdict']}")


@main.command()
@click.option("--findings", "findings_path", type=click.Path(exists=True), required=True, help="Agent findings JSON.")
@click.option("--answer-key", "answer_key_path", type=click.Path(exists=True), required=True, help="Ground truth JSON.")
def score_cmd(findings_path: str, answer_key_path: str) -> None:
    """Score agent findings against the case answer key."""
    payload = orjson.loads(Path(findings_path).read_bytes())
    raw_findings = payload.get("findings", []) if isinstance(payload, dict) else payload
    answer = AnswerKey.model_validate_json(Path(answer_key_path).read_bytes())
    report = score(raw_findings, answer)
    click.echo(orjson.dumps(report.model_dump(), option=orjson.OPT_INDENT_2).decode())


# Click's command attribute is `score_cmd` to avoid shadowing the imported score().
main.add_command(score_cmd, name="score")


@main.command()
@click.option("--seeds", type=int, default=10, help="Number of seeds to score against.")
@click.option("--agents", default="court,dhyabi2,marez8505", help="Comma-separated agent ids.")
def leaderboard(seeds: int, agents: str) -> None:
    """Run leaderboard across N seeds × M agents and emit a scorecard."""
    raise NotImplementedError(
        f"leaderboard(seeds={seeds}, agents={agents!r}) — landing Thursday 6/5"
    )


@main.command()
@click.option("--transcript", "transcript_path", type=click.Path(exists=True), required=True, help="Transcript file (JSONL).")
@click.option("--hmac/--no-hmac", "check_hmac", default=False, help="Also verify the HMAC signature (.sig sidecar). Requires HEXBREAKER_HMAC_PASSWORD.")
def verify_cmd(transcript_path: str, check_hmac: bool) -> None:
    """Verify the hash chain (and optionally the HMAC signature) on a Court transcript."""
    if check_hmac:
        result = verify_signature(transcript_path)
        if result.ok:
            click.echo(f"chain + HMAC OK: {transcript_path}")
        else:
            if not result.chain_ok:
                click.echo(f"chain INVALID: {result.chain_reason}", err=True)
            if not result.hmac_ok:
                click.echo(f"HMAC INVALID: {result.reason}", err=True)
            raise SystemExit(1)
    else:
        ok, reason = verify(transcript_path)
        if ok:
            click.echo(f"chain OK: {transcript_path}  (run with --hmac to also verify signature)")
        else:
            click.echo(f"chain INVALID: {reason}", err=True)
            raise SystemExit(1)


main.add_command(verify_cmd, name="verify")


@main.command()
@click.option("--transcript", "transcript_path", type=click.Path(exists=True), required=True, help="Transcript file (JSONL) to sign.")
def sign_cmd(transcript_path: str) -> None:
    """Sign a Court transcript with HMAC-SHA256 (Valhuntir pattern).

    Reads HEXBREAKER_HMAC_PASSWORD from the environment. Writes <transcript>.sig
    next to the file. The .sig binds the chain head AND record count, so
    truncation or append is detected even when the post-tamper prefix is
    independently valid.
    """
    sig = sign_transcript(transcript_path)
    click.echo(f"signed: {transcript_path}")
    click.echo(f"  algorithm: {sig.algorithm}")
    click.echo(f"  records:   {sig.record_count}")
    click.echo(f"  head:      {sig.chain_head}")
    click.echo(f"  hmac:      {sig.hmac_hex[:16]}...")


main.add_command(sign_cmd, name="sign")


if __name__ == "__main__":
    main()
