from __future__ import annotations

import pytest

from aegis.core.enums import Severity
from aegis.osv.cvss import score_vector


@pytest.mark.parametrize(
    ("vector", "expected_score", "expected_severity"),
    [
        # Official FIRST examples (CVSS v3.1 spec, section 8.1)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.CRITICAL),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, Severity.CRITICAL),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.8, Severity.LOW),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3, Severity.MEDIUM),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, Severity.HIGH),
        # CVSS v3.0 uses the same base formula
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.CRITICAL),
        # All metrics at None
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, Severity.UNKNOWN),
    ],
)
def test_known_vectors(vector: str, expected_score: float, expected_severity: Severity) -> None:
    result = score_vector(vector)
    assert result.score == pytest.approx(expected_score, abs=0.01)
    assert result.severity_band is expected_severity


def test_cvss_v4_returns_none_with_reason() -> None:
    result = score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
    assert result.score is None
    assert result.version == "v4"
    assert result.reason is not None and "v4" in result.reason.lower()


def test_unknown_prefix_returns_none() -> None:
    result = score_vector("not a cvss vector")
    assert result.score is None
    assert result.version == "unknown"


def test_missing_metrics_returns_none() -> None:
    result = score_vector("CVSS:3.1/AV:N/AC:L")
    assert result.score is None
    assert "missing" in (result.reason or "")


def test_invalid_metric_value_returns_none() -> None:
    result = score_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result.score is None
    assert result.reason is not None
