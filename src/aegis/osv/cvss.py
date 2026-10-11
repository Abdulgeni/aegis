"""CVSS base score computation.

Supports CVSS v3.0 and v3.1 vectors, which share the same base score formula. CVSS v2
is not supported (its formula is different and OSV rarely emits it; we return None).
CVSS v4 uses the FIRST macrovector lookup tables; we do not approximate it, so v4 vectors
return ``None`` with an explicit reason and callers should warn.

The single public entry point is ``score_vector(vector)`` which returns a
``CvssResult`` with ``score``, ``severity_band``, ``version``, and (when scoring failed)
``reason``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from aegis.core.enums import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


@dataclass(frozen=True)
class CvssResult:
    """Result of scoring one CVSS vector.

    ``score`` is ``None`` when the vector could not be scored; ``reason`` explains why.
    ``severity_band`` is derived from ``score`` via the standard CVSS qualitative bands.
    """

    score: float | None
    severity_band: Severity
    version: str
    reason: str | None = None


def score_vector(vector: str) -> CvssResult:
    """Score a CVSS vector. Returns a result with ``score=None`` if unsupported."""
    version = _detect_version(vector)
    if version == "v3":
        return _score_v3(vector)
    if version == "v4":
        return CvssResult(
            score=None,
            severity_band=Severity.UNKNOWN,
            version="v4",
            reason="CVSS v4 base score uses the FIRST macrovector table and is not implemented",
        )
    return CvssResult(
        score=None,
        severity_band=Severity.UNKNOWN,
        version="unknown",
        reason="vector does not start with CVSS:3 or CVSS:4",
    )


def _detect_version(vector: str) -> str:
    text = vector.strip().upper()
    if text.startswith("CVSS:3.0/") or text.startswith("CVSS:3.1/"):
        return "v3"
    if text.startswith("CVSS:4.0/"):
        return "v4"
    return "unknown"


def _score_v3(vector: str) -> CvssResult:
    metrics = _parse_metrics(vector)
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = required - set(metrics)
    if missing:
        return CvssResult(
            score=None,
            severity_band=Severity.UNKNOWN,
            version="v3",
            reason=f"missing metrics: {', '.join(sorted(missing))}",
        )
    try:
        exploitability = (
            8.22
            * _AV[metrics["AV"]]
            * _AC[metrics["AC"]]
            * (_PR_CHANGED if metrics["S"] == "C" else _PR_UNCHANGED)[metrics["PR"]]
            * _UI[metrics["UI"]]
        )
        iss = 1.0 - (
            (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        )
        scope_changed = metrics["S"] == "C"
        impact = (
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
            if scope_changed
            else 6.42 * iss
        )
    except KeyError as exc:
        return CvssResult(
            score=None,
            severity_band=Severity.UNKNOWN,
            version="v3",
            reason=f"invalid metric value: {exc}",
        )
    # CVSS v3.1 spec section 7.1: if Impact <= 0, Base Score is 0 regardless of exploitability.
    if impact <= 0:
        return CvssResult(score=0.0, severity_band=Severity.UNKNOWN, version="v3")
    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)
    score = _roundup(raw)
    return CvssResult(score=score, severity_band=Severity.from_score(score), version="v3")


def _parse_metrics(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, _, value = part.partition(":")
        if key and value:
            metrics[key.upper()] = value.upper()
    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: round up to one decimal place, avoiding float error."""
    return math.ceil(value * 10) / 10 if value > 0 else 0.0
