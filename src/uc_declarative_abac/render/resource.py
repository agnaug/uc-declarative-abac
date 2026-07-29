from __future__ import annotations

import os
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from uc_declarative_abac.principals import Principal
from uc_declarative_abac.securables import Securable
from uc_declarative_abac.types import SecurableType

if TYPE_CHECKING:
    from uc_declarative_abac.orchestrator import OrchestratorDiffsResult

_TYPE_ORDER = {
    SecurableType.CATALOG: 0,
    SecurableType.SCHEMA: 1,
    SecurableType.TABLE: 2,
    SecurableType.VOLUME: 3,
    SecurableType.FUNCTION: 4,
    SecurableType.COLUMN: 5,
}


@dataclass(frozen=True)
class _PlanCount:
    add: int = 0
    change: int = 0
    destroy: int = 0


@dataclass(frozen=True)
class _ChangeEntry:
    symbol: str
    text: str


def _resource_sort_key(resource_key: tuple[str, str]) -> tuple[int, str]:
    kind, name = resource_key
    if kind == "governed_tag":
        return (100, name)
    if kind == "group":
        return (101, name)
    try:
        sec_type = SecurableType(kind.upper())
    except ValueError:
        return (999, name)
    return (_TYPE_ORDER.get(sec_type, 999), name)


def _resource_label(resource_key: tuple[str, str]) -> str:
    kind, name = resource_key
    return f'{kind} "{name}"'


def _display_set(value: frozenset[str] | frozenset[Principal]) -> str:
    if not value:
        return '""'
    rendered = sorted(
        v.name if isinstance(v, Principal) else str(v) for v in value
    )
    return ", ".join(f'"{v}"' for v in rendered)


def _securable_change_label(securable: Securable) -> str:
    return securable.securable_type.value.lower()


def _supports_color(*, no_color: bool) -> bool:
    if no_color:
        return False
    if os.getenv("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _paint(symbol: str, *, color: bool) -> str:
    if not color:
        return symbol
    if symbol == "+":
        return f"\033[32m{symbol}\033[0m"
    if symbol == "~":
        return f"\033[33m{symbol}\033[0m"
    return f"\033[31m{symbol}\033[0m"


def _append_change(
    grouped: dict[tuple[str, str], list[_ChangeEntry]],
    resource_key: tuple[str, str],
    symbol: str,
    text: str,
) -> None:
    grouped[resource_key].append(_ChangeEntry(symbol=symbol, text=text))


def _build_grouped_lines(
    diffs: OrchestratorDiffsResult,
    *,
    color: bool,
) -> tuple[dict[tuple[str, str], list[_ChangeEntry]], _PlanCount]:
    grouped: dict[tuple[str, str], list[_ChangeEntry]] = defaultdict(list)
    add = change = destroy = 0

    for update in diffs.securable_diff.attributes_to_update:
        key = (update.securable_type.value.lower(), update.full_name)
        _append_change(
            grouped,
            key,
            "~",
            f'{update.attribute} = {_display_set(update.old_value)} -> {_display_set(update.new_value)}',
        )
        change += 1

    for securable in diffs.securable_diff.securables_to_create:
        key = (securable.securable_type.value.lower(), securable.full_name)
        _append_change(
            grouped, key, "+", f"create {_securable_change_label(securable)}",
        )
        add += 1

    for securable in diffs.securable_diff.securables_to_replace:
        key = (securable.securable_type.value.lower(), securable.full_name)
        _append_change(
            grouped, key, "~", f"replace {_securable_change_label(securable)}",
        )
        change += 1

    for tag in diffs.tag_diff.to_add:
        key = (tag.securable_type.value.lower(), tag.securable_full_name)
        _append_change(
            grouped, key, "+", f'tag.{tag.tag_name} = "{tag.tag_value}"',
        )
        add += 1

    for tag in diffs.tag_diff.to_update:
        key = (tag.securable_type.value.lower(), tag.securable_full_name)
        old = diffs.tag_diff.old_values.get(
            (tag.securable_type, tag.securable_full_name, tag.tag_name), ""
        ) or ""
        _append_change(
            grouped, key, "~", f'tag.{tag.tag_name} = "{old}" -> "{tag.tag_value}"',
        )
        change += 1

    for tag in diffs.tag_diff.to_remove:
        key = (tag.securable_type.value.lower(), tag.securable_full_name)
        _append_change(grouped, key, "-", f"tag.{tag.tag_name}")
        destroy += 1

    for policy in diffs.policy_diff.to_create:
        key = (policy.securable_type.value.lower(), policy.securable_full_name)
        _append_change(
            grouped,
            key,
            "+",
            f"{policy.policy_type.value}_policy {policy.name}",
        )
        add += 1

    for policy in diffs.policy_diff.to_replace:
        key = (policy.securable_type.value.lower(), policy.securable_full_name)
        _append_change(
            grouped,
            key,
            "~",
            f"{policy.policy_type.value}_policy {policy.name}",
        )
        change += 1

    for policy in diffs.policy_diff.to_delete:
        key = (policy.securable_type.value.lower(), policy.securable_full_name)
        _append_change(
            grouped,
            key,
            "-",
            f"{policy.policy_type.value}_policy {policy.name}",
        )
        destroy += 1

    for privilege in diffs.privilege_diff.to_grant:
        key = (privilege.securable_type.value.lower(), privilege.securable_full_name)
        _append_change(
            grouped,
            key,
            "+",
            f'{privilege.privilege_type.value.upper()} to "{privilege.principal.name}"',
        )
        add += 1

    for privilege in diffs.privilege_diff.to_revoke:
        key = (privilege.securable_type.value.lower(), privilege.securable_full_name)
        _append_change(
            grouped,
            key,
            "-",
            f'{privilege.privilege_type.value.upper()} from "{privilege.principal.name}"',
        )
        destroy += 1

    for governed in diffs.governed_tag_diff.to_create:
        key = ("governed_tag", governed.name)
        _append_change(grouped, key, "+", "create")
        add += 1
    for governed in diffs.governed_tag_diff.to_update:
        key = ("governed_tag", governed.name)
        _append_change(grouped, key, "~", "update")
        change += 1
    for governed in diffs.governed_tag_diff.to_delete:
        key = ("governed_tag", governed.name)
        _append_change(grouped, key, "-", "delete")
        destroy += 1

    for group_name, members in diffs.group_diff.groups_to_create.items():
        key = ("group", group_name)
        _append_change(grouped, key, "+", "create")
        if members:
            _append_change(
                grouped,
                key,
                "~",
                "members += " + ", ".join(f'"{m.name}"' for m in sorted(members, key=lambda p: p.name)),
            )
        add += 1
    for rename in diffs.group_diff.groups_to_rename:
        key = ("group", rename.old_display_name)
        _append_change(grouped, key, "~", f'name = "{rename.old_display_name}" -> "{rename.new_display_name}"')
        change += 1
    for group_name, members in diffs.group_diff.members_to_add.items():
        key = ("group", group_name)
        _append_change(
            grouped,
            key,
            "~",
            "members += " + ", ".join(f'"{m.name}"' for m in sorted(members, key=lambda p: p.name)),
        )
        change += len(members)
    for group_name, members in diffs.group_diff.members_to_remove.items():
        key = ("group", group_name)
        _append_change(
            grouped,
            key,
            "~",
            "members -= " + ", ".join(f'"{m.name}"' for m in sorted(members, key=lambda p: p.name)),
        )
        change += len(members)

    return grouped, _PlanCount(add=add, change=change, destroy=destroy)


def render_resource_plan(
    diffs: OrchestratorDiffsResult,
    *,
    no_color: bool = False,
) -> list[str]:
    use_color = _supports_color(no_color=no_color)
    grouped, counts = _build_grouped_lines(diffs, color=use_color)
    if not grouped:
        return ["No changes. Infrastructure is up-to-date."]

    lines = ["", "UC Declarative ABAC will perform the following actions:", ""]
    for resource_key in sorted(grouped.keys(), key=_resource_sort_key):
        entry_lines = grouped[resource_key]
        header_symbol = entry_lines[0].symbol
        lines.append(f"  {_paint(header_symbol, color=use_color)} {_resource_label(resource_key)}")
        for entry in entry_lines:
            lines.append(f"      {_paint(entry.symbol, color=use_color)} {entry.text}")
        lines.append("")

    lines.append(
        f"Plan: {counts.add} to add, {counts.change} to change, {counts.destroy} to destroy."
    )
    return lines
