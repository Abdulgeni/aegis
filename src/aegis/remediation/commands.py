"""Ecosystem-specific upgrade command suggestions.

Direct dependencies get a normal upgrade command. Transitive dependencies get a
recommendation to upgrade the direct ancestor that pulls them in, with override/constraint
alternatives in case the ancestor cannot be upgraded in isolation.
"""

from __future__ import annotations

from collections.abc import Sequence

from aegis.core.enums import Ecosystem
from aegis.core.models import Dependency


def suggest_command(
    ecosystem: Ecosystem,
    name: str,
    fixed: str,
    direct: bool | None,
    group: Sequence[Dependency],
) -> tuple[str | None, tuple[str, ...]]:
    """Return ``(primary_command, alternatives)`` for one fix."""
    if ecosystem is Ecosystem.PYPI:
        return _pypi(name, fixed, direct, group)
    if ecosystem is Ecosystem.NPM:
        return _npm(name, fixed, direct, group)
    if ecosystem is Ecosystem.GO:
        return _go(name, fixed, direct, group)
    return None, ()


def _pypi(
    name: str, fixed: str, direct: bool | None, group: Sequence[Dependency]
) -> tuple[str | None, tuple[str, ...]]:
    if direct or direct is None:
        return f'pip install "{name}>={fixed}"', ()
    parent = _direct_ancestor(group)
    if parent is None:
        return (
            None,
            (
                f'pip install "{name}>={fixed}"  # transitive; upgrade the parent instead if possible',
                f'echo "{name}>={fixed}" >> constraints.txt  # enforce via a constraints file',
            ),
        )
    return (
        f'pip install --upgrade "{parent}"',
        (f'echo "{name}>={fixed}" >> constraints.txt',),
    )


def _npm(
    name: str, fixed: str, direct: bool | None, group: Sequence[Dependency]
) -> tuple[str | None, tuple[str, ...]]:
    if direct or direct is None:
        return f"npm install {name}@^{fixed}", ()
    parent = _direct_ancestor(group)
    if parent is None:
        return (
            None,
            (
                f"npm install {name}@{fixed}  # transitive; upgrade the parent instead if possible",
                f'npm pkg set overrides."{name}"="{fixed}"  # enforce via overrides',
            ),
        )
    return (
        f"npm install --save {parent}@latest",
        (f'npm pkg set overrides."{name}"="{fixed}"',),
    )


def _go(
    name: str, fixed: str, direct: bool | None, group: Sequence[Dependency]
) -> tuple[str | None, tuple[str, ...]]:
    target = fixed if fixed.startswith("v") else f"v{fixed}"
    if direct or direct is None:
        return f"go get {name}@{target}", ()
    parent = _direct_ancestor(group)
    if parent is None:
        return (
            None,
            (f"go get {name}@{target}  # transitive; update the parent module",),
        )
    return (f"go get {parent}@latest", (f"go get {name}@{target}",))


def _direct_ancestor(group: Sequence[Dependency]) -> str | None:
    """The name of the nearest dependency in ``group``'s resolved_from chain, if any."""
    for dep in group:
        chain = dep.resolved_from
        if chain:
            parent_name, _, _ = chain.partition("@")
            if parent_name:
                return parent_name
    return None
