#!/usr/bin/env python3
"""SIH26145 — Shared helpers for the per-threat detectors."""
from __future__ import annotations

import math
from collections.abc import Iterable


def entropy_bits(values: Iterable[int]) -> float:
    """Shannon entropy (bits) of a count histogram."""
    counts = list(values)
    n = sum(counts)
    if n <= 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in counts if c > 0)


def char_entropy(text: str) -> float:
    """Per-character entropy (bits/char) of a string like a domain name."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return entropy_bits(counts.values())


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def clip(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))