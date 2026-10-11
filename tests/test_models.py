from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.core.enums import Ecosystem
from aegis.core.models import Dependency


def _dep(**overrides: object) -> Dependency:
    data: dict[str, object] = {
        "name": "requests",
        "version": "2.0.0",
        "ecosystem": Ecosystem.PYPI,
        "direct": True,
        "source": "poetry.lock",
    }
    data.update(overrides)
    return Dependency.model_validate(data)


def test_dependency_is_frozen() -> None:
    dep = _dep()
    with pytest.raises(ValidationError):
        dep.name = "other"  # type: ignore[misc]


def test_dependency_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        _dep(surprise=1)


def test_dependency_direct_may_be_unknown() -> None:
    assert _dep(direct=None).direct is None


def test_dependency_line_is_one_based() -> None:
    assert _dep(line=1).line == 1
    with pytest.raises(ValidationError):
        _dep(line=0)


def test_dependency_serializes_ecosystem_value() -> None:
    assert _dep().model_dump(mode="json")["ecosystem"] == "PyPI"


def test_dependency_is_hashable() -> None:
    assert len({_dep(), _dep()}) == 1
