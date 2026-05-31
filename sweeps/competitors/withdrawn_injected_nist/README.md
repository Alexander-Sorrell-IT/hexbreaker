# WITHDRAWN — do not cite

These JSON files are the outputs of the **withdrawn** batched `scripts/court_on_nist.py`
pipeline, which injected literal ground-truth answers into the prompt
("=== PRE-COMPUTED HINTS ===") and scored by substring match. The resulting
numbers (notably the **95.08% F1**) measured string-copying, **not forensics**, and
were produced by a single batched LLM call with **no** Court FSM / Judge /
Provocateur / hash-chained transcript.

They are archived here for provenance only. They are **not valid measurements** and
must not be cited as Hexbreaker accuracy. See `docs/accuracy.md` §3.2 and the
withdrawal notes in `docs/devpost.md` / `README.md`.

The genuine, honest Court-on-NIST path is `scripts/court_on_nist_fsm.py` (real FSM
Court on real recycle-bin evidence, no answer injection), whose signed result is
reported in `docs/accuracy.md`. The real competitor measurement that *is* valid —
dhyabi2 scoring 0% on NIST under the DeepSeek+Ubuntu constraint — lives one level up
(`../score_deepseek.json`, `../run_deepseek.log`, `../hacking_case_deepseek.json`).
