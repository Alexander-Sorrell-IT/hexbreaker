# Bypass coverage — every guardrail has a test that *attempts the bypass and asserts it fails*

This is the C4 "tested for bypass" index: for each architectural guardrail, the test
that tries to defeat it and asserts the defense holds. Every entry below is a real,
passing test function (run `PYTHONPATH=src python -m pytest -q`). The tests live in
their subsystem files (not moved here, to keep imports/collection stable); this file is
the map. See also the security tables in [`docs/architecture.md`](../../docs/architecture.md).

## Citation / referential integrity (Layer 1 + 4)
- Fabricated `step_id` → rejected: `tests/test_validator.py::test_verdict_rejected_on_fabricated_step_id`
- Hash substitution on a cited step → rejected: `tests/test_validator.py::test_verdict_rejected_on_hash_substitution`
- Citation pointing at a non-tool step → rejected: `tests/test_validator.py::test_verdict_rejected_when_citation_points_to_non_tool_step`
- Orchestrator re-enforcement (fabricated step, session stays open): `tests/test_orchestrator.py::test_verdict_with_fabricated_step_is_rejected_session_stays_open`

## Forced tool-call FSM (Layer 2)
- Verdict before observing a tool → rejected: `tests/test_orchestrator.py::test_premature_verdict_is_rejected_but_session_stays_open`

## Strict schema (Layer 3)
- Extra/forbidden fields → rejected: `tests/test_schema.py::test_verdict_extras_rejected`
- Bad `step_id` / `stdout_hash` regex → rejected: `tests/test_schema.py::test_step_reference_rejects_bad_step_id`, `::test_step_reference_rejects_bad_hash`
- Duplicate citations / unknown verdict kind → rejected: `tests/test_schema.py::test_verdict_rejects_duplicate_citations`, `::test_verdict_rejects_unknown_kind`

## Hash chain + sidecar bytes (Layer 4)
- Record content tampering → caught: `tests/test_transcript.py::test_verify_detects_content_tampering`
- Sidecar-byte tampering (clean→evil on disk) → caught: `tests/test_transcript.py::test_verify_detects_sidecar_byte_tampering`
- Missing sidecar → caught: `tests/test_transcript.py::test_verify_detects_missing_sidecar`

## HMAC signing (Layer 5)
- Tampered record content → caught: `tests/test_hmac_chain.py::test_verify_detects_tampered_record_content`
- **Full-chain recompute forgery** (the attack the bare SHA chain can't stop) → caught by HMAC: `tests/test_hmac_chain.py::test_hmac_detects_full_chain_recompute_forgery`

## Deterministic Judge (Layer 6 / corroboration)
- Single-tool CONFIRM → downgraded to CONTESTED (JR-01): `tests/test_judge.py::test_jr01_downgrades_confirmed_with_single_tool`, `::test_session_downgrades_single_signal_confirmed`
- Provocateur leak echoed in `challenge_text` → downgraded (JR-02), case/whitespace-insensitive: `tests/test_provocateur.py::test_jr02_downgrades_when_challenge_text_echoes_leak_token`

## Path-traversal / command isolation (security boundaries)
- Case `mock_outputs` absolute / `..` / drive / backslash paths → rejected: `tests/test_forge_case.py::test_mock_outputs_rejects_dot_dot_traversal`, `::test_mock_outputs_rejects_absolute_path`, `::test_mock_outputs_rejects_windows_backslash_traversal`, `::test_mock_outputs_rejects_windows_drive_path`
- Runtime traversal defense-in-depth: `tests/test_forge_case.py::test_mock_runner_defense_in_depth_against_runtime_traversal`
- Transcript sidecar traversal / absolute path → refused: `tests/test_security_transcript.py::test_render_transcript_refuses_traversal_stdout_path`, `::test_render_transcript_refuses_absolute_stdout_path`
- Poisoned pre-existing transcript in a case dir → refused: `tests/test_security_transcript.py::test_run_court_refuses_preexisting_transcript_in_case_dir`
- Unsupported/destructive tool name → rejected: `tests/test_tools.py::test_run_tool_rejects_unsupported_tool`
- MCP dispatch of unsupported/unknown tool → refused: `tests/test_mcp_server.py::test_dispatch_refuses_unsupported_sift_tool`, `::test_dispatch_refuses_unknown_mcp_tool`

## Finding → tool-execution trace (audit trail, C5)
- Tampered sidecar / missing sidecar / fabricated citation → trace fails, exits non-zero: `tests/test_trace.py::test_tampered_sidecar_is_caught`, `::test_missing_sidecar_is_caught`, `::test_fabricated_citation_is_caught`
