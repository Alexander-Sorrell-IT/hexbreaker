"""Hexbreaker Scorer — deterministic exact-match grading.

No fuzzy matching, no SequenceMatcher, no LLM-as-judge.
Compares agent Findings[] to the case's ground-truth answer key.
Emits ScoreReport with precision, recall, F1 + per-finding TP/FP/FN.
"""
