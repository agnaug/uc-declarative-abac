from __future__ import annotations

from uc_declarative_abac.governed_tags import GovernedTagDiff
from uc_declarative_abac.orchestrator import OrchestratorDiffsResult
from uc_declarative_abac.policies import PolicyDiff
from uc_declarative_abac.principals import GroupDiff
from uc_declarative_abac.privileges import PrivilegeDiff
from uc_declarative_abac.render import render_json_plan
from uc_declarative_abac.securables import SecurableDiff
from uc_declarative_abac.tags import TagDiff


def _empty_diffs() -> OrchestratorDiffsResult:
    return OrchestratorDiffsResult(
        group_diff=GroupDiff(),
        securable_diff=SecurableDiff(),
        governed_tag_diff=GovernedTagDiff(),
        tag_diff=TagDiff(),
        policy_diff=PolicyDiff(),
        privilege_diff=PrivilegeDiff(),
    )


def test_render_json_plan_has_expected_top_level_shape():
    payload = render_json_plan(
        _empty_diffs(),
        mode="plan",
        dry_run=True,
    )
    assert payload["format_version"] == "1"
    assert payload["mode"] == "plan"
    assert payload["dry_run"] is True
    assert payload["summary"] == {"add": 0, "change": 0, "destroy": 0}
    assert payload["resources"] == []
    assert payload["warnings"] == []
    assert payload["errors"] == []
