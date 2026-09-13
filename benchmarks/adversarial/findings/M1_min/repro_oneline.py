"""Minimized 1-line reproduction for FIND-M1 (cycle_67/adversary/04).

Audit finding: compute_check_digits lacks an isinstance() guard and
raises AttributeError (or TypeError for bytes) on non-string input.

Run with: python benchmarks/adversarial/findings/M1_min/repro_oneline.py
Expected: prints a single AttributeError, exits non-zero (Python default
for an uncaught exception is exit 1). The 'bug' is reproduced.

This is the canonical 1-liner — every entry below is functionally a
shorter equivalent; we use the None case because it is the most likely
caller mistake (forgot to validate input before passing to the function).
"""
import iban_pure

iban_pure.compute_check_digits(None)
