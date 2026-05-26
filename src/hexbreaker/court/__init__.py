"""Hexbreaker Court — 5-role adversarial forensic agent.

Roles:
- Prosecutor   : emits forensic claims with cited evidence
- Defender     : falsifies, presumption of innocence
- Witness      : independent toolset, called on demand
- Judge        : deterministic Python function — NO LLM call. Rules JR-01..N
- Provocateur  : injects prompt-injection payloads in every run

Output: hash-chained, HMAC-signed CourtRecord stream.
See PLAN_EVILFORGE.md §3.
"""
