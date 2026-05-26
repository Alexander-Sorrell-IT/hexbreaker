"""Hexbreaker CLI entry point. Subcommands wired in as each subsystem lands."""

import click


@click.group()
@click.version_option()
def main() -> None:
    """Hexbreaker — adversarial DFIR triage and benchmark."""


@main.command()
@click.option("--seed", type=int, required=True, help="Case generation seed.")
@click.option("--template", default="all", help="Case template id or 'all'.")
@click.option("--out", type=click.Path(), required=True, help="Output case directory.")
def generate(seed: int, template: str, out: str) -> None:
    """Generate a synthetic DFIR case from a seed."""
    raise NotImplementedError(
        f"forge.generate(seed={seed}, template={template!r}, out={out!r}) — landing Tuesday 5/27"
    )


@main.command()
@click.option("--agent", required=True, help="Agent id: court | dhyabi2 | marez8505 | valhuntir | sift")
@click.option("--case", type=click.Path(exists=True), required=True, help="Case directory.")
@click.option("--out", type=click.Path(), required=True, help="Findings output path.")
def run(agent: str, case: str, out: str) -> None:
    """Run an agent on a case and capture findings."""
    raise NotImplementedError(
        f"runner.run(agent={agent!r}, case={case!r}, out={out!r}) — landing Wednesday 5/28"
    )


@main.command()
@click.option("--findings", type=click.Path(exists=True), required=True, help="Agent findings JSON.")
@click.option("--answer-key", type=click.Path(exists=True), required=True, help="Ground truth JSON.")
def score(findings: str, answer_key: str) -> None:
    """Score agent findings against the case answer key."""
    raise NotImplementedError(
        f"scorer.score(findings={findings!r}, answer_key={answer_key!r}) — landing Wednesday 5/28"
    )


@main.command()
@click.option("--seeds", type=int, default=10, help="Number of seeds to score against.")
@click.option("--agents", default="court,dhyabi2,marez8505", help="Comma-separated agent ids.")
def leaderboard(seeds: int, agents: str) -> None:
    """Run leaderboard across N seeds × M agents and emit a scorecard."""
    raise NotImplementedError(
        f"leaderboard(seeds={seeds}, agents={agents!r}) — landing Thursday 6/5"
    )


@main.command()
@click.option("--run-id", required=True, help="Run identifier to verify.")
def verify(run_id: str) -> None:
    """Verify hash chain + HMAC signatures on a Court run transcript."""
    raise NotImplementedError(
        f"transcript verification for run_id={run_id!r} — landing Tuesday 6/3"
    )


if __name__ == "__main__":
    main()
