from __future__ import annotations

from typing import TYPE_CHECKING

from uc_declarative_abac.render.resource import _build_grouped_lines, _resource_sort_key

if TYPE_CHECKING:
    from uc_declarative_abac.orchestrator import OrchestratorDiffsResult


def render_json_plan(
    diffs: OrchestratorDiffsResult,
    *,
    mode: str,
    dry_run: bool,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
) -> dict[str, object]:
    grouped, counts = _build_grouped_lines(diffs, color=False)
    resources: list[dict[str, object]] = []
    for resource_key in sorted(grouped.keys(), key=_resource_sort_key):
        kind, full_name = resource_key
        resources.append(
            {
                "type": kind,
                "full_name": full_name,
                "changes": [
                    {
                        "op": entry.symbol,
                        "description": entry.text,
                    }
                    for entry in grouped[resource_key]
                ],
            }
        )
    return {
        "format_version": "1",
        "mode": mode,
        "dry_run": dry_run,
        "summary": {
            "add": counts.add,
            "change": counts.change,
            "destroy": counts.destroy,
        },
        "resources": resources,
        "warnings": warnings or [],
        "errors": errors or [],
    }
