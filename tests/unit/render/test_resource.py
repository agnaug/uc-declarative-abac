from __future__ import annotations

from uc_declarative_abac.governed_tags import GovernedTagDiff
from uc_declarative_abac.orchestrator import OrchestratorDiffsResult
from uc_declarative_abac.policies import PolicyDiff
from uc_declarative_abac.principals import GroupDiff, Principal
from uc_declarative_abac.privileges import PrivilegeDiff, SecurablePrivilege
from uc_declarative_abac.render import render_resource_plan
from uc_declarative_abac.securables import SecurableDiff
from uc_declarative_abac.tags import SecurableTag, TagDiff
from uc_declarative_abac.types import PrincipalType, PrivilegeType, SecurableType


def _empty_diffs() -> OrchestratorDiffsResult:
    return OrchestratorDiffsResult(
        group_diff=GroupDiff(),
        securable_diff=SecurableDiff(),
        governed_tag_diff=GovernedTagDiff(),
        tag_diff=TagDiff(),
        policy_diff=PolicyDiff(),
        privilege_diff=PrivilegeDiff(),
    )


def test_resource_renderer_reports_no_changes():
    lines = render_resource_plan(_empty_diffs(), no_color=True)
    assert lines == ["No changes. Infrastructure is up-to-date."]


def test_resource_renderer_groups_multiple_changes_on_same_resource():
    principal = Principal(
        principal_type=PrincipalType.GROUP,
        identifier="analysts",
        name="analysts",
    )
    tag = SecurableTag(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.sales.orders",
        tag_name="pii",
        tag_value="true",
    )
    grant = SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.sales.orders",
        principal=principal,
        privilege_type=PrivilegeType.SELECT,
    )
    diffs = OrchestratorDiffsResult(
        group_diff=GroupDiff(),
        securable_diff=SecurableDiff(),
        governed_tag_diff=GovernedTagDiff(),
        tag_diff=TagDiff(to_add={tag}),
        policy_diff=PolicyDiff(),
        privilege_diff=PrivilegeDiff(to_grant={grant}),
    )

    text = "\n".join(render_resource_plan(diffs, no_color=True))
    assert 'table "cat.sales.orders"' in text
    assert 'tag.pii = "true"' in text
    assert 'SELECT to "analysts"' in text
    assert "Plan: 2 to add, 0 to change, 0 to destroy." in text
