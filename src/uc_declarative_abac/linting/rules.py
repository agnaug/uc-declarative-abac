from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from uc_declarative_abac.configs import (
    GrantPolicyConfig,
    MaskPolicyConfig,
    ResourcesConfig,
)
from uc_declarative_abac.types import SecurableType


@dataclass(frozen=True)
class LintViolation:
    rule_id: str
    severity: str
    location: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class LintRules:
    key_only_tags: frozenset[str] = frozenset({"domain", "subdomain"})
    key_value_tags: frozenset[str] = frozenset()
    require_mask_to: bool = True
    require_mask_except: bool = True
    fail_on_schema_grants: bool = True
    schema_grant_severity: str = "warning"


@dataclass(frozen=True)
class LintResult:
    violations: tuple[LintViolation, ...] = field(default_factory=tuple)

    @property
    def has_errors(self) -> bool:
        return any(v.severity == "error" for v in self.violations)

    def as_dict(self) -> dict[str, object]:
        return {
            "violations": [v.as_dict() for v in self.violations],
            "count": len(self.violations),
            "error_count": sum(1 for v in self.violations if v.severity == "error"),
            "warning_count": sum(1 for v in self.violations if v.severity == "warning"),
        }


def _load_yaml_mapping(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Lint rules file {path} must contain a YAML mapping.")
    return data


def _to_frozenset_of_str(value: object, *, field_name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list):
        raise ValueError(f"Lint rules field '{field_name}' must be a list of strings.")
    members: list[str] = []
    for entry in value:
        if not isinstance(entry, str):
            raise ValueError(f"Lint rules field '{field_name}' must contain only strings.")
        stripped = entry.strip()
        if stripped:
            members.append(stripped)
    return frozenset(members)


def load_lint_rules(path: Path | None) -> LintRules:
    if path is None:
        return LintRules()
    raw = _load_yaml_mapping(path)
    key_only_tags = _to_frozenset_of_str(raw.get("key_only_tags"), field_name="key_only_tags")
    key_value_tags = _to_frozenset_of_str(raw.get("key_value_tags"), field_name="key_value_tags")
    if key_only_tags & key_value_tags:
        overlap = sorted(key_only_tags & key_value_tags)
        raise ValueError(f"Tags cannot be both key-only and key-value: {overlap}")
    return LintRules(
        key_only_tags=key_only_tags or LintRules().key_only_tags,
        key_value_tags=key_value_tags,
        require_mask_to=bool(raw.get("require_mask_to", True)),
        require_mask_except=bool(raw.get("require_mask_except", True)),
        fail_on_schema_grants=bool(raw.get("fail_on_schema_grants", True)),
        schema_grant_severity=str(raw.get("schema_grant_severity", "warning")).lower(),
    )


def _iter_policy_locations(config: ResourcesConfig):
    for catalog in config.catalogs.values():
        for policy in catalog.policies or []:
            yield f"catalog:{catalog.full_name}:policy:{policy.name}", policy
        for schema in catalog.schemas or []:
            for policy in schema.policies or []:
                yield f"schema:{schema.full_name}:policy:{policy.name}", policy
            for table in schema.tables or []:
                for policy in table.policies or []:
                    yield f"table:{table.full_name}:policy:{policy.name}", policy


def _iter_taggable_locations(config: ResourcesConfig):
    for catalog in config.catalogs.values():
        yield f"catalog:{catalog.full_name}", catalog.tags or {}
        for schema in catalog.schemas or []:
            yield f"schema:{schema.full_name}", schema.tags or {}
            for table in schema.tables or []:
                yield f"table:{table.full_name}", table.tags or {}
                for column in table.columns or []:
                    yield f"column:{column.full_name}", column.tags or {}
            for volume in schema.volumes or []:
                yield f"volume:{volume.full_name}", volume.tags or {}


def lint_config(config: ResourcesConfig, rules: LintRules) -> LintResult:
    violations: list[LintViolation] = []

    for location, tags in _iter_taggable_locations(config):
        for key, value in tags.items():
            if key in rules.key_only_tags and value:
                violations.append(
                    LintViolation(
                        rule_id="tag.key_only",
                        severity="error",
                        location=location,
                        message=f"Tag '{key}' must be key-only (valueless), found value '{value}'.",
                    )
                )
            if key in rules.key_value_tags and not value:
                violations.append(
                    LintViolation(
                        rule_id="tag.key_value",
                        severity="error",
                        location=location,
                        message=f"Tag '{key}' must be key-value, found valueless tag.",
                    )
                )

    for location, policy in _iter_policy_locations(config):
        if isinstance(policy, MaskPolicyConfig):
            if rules.require_mask_to and not policy.to:
                violations.append(
                    LintViolation(
                        rule_id="mask.to_required",
                        severity="error",
                        location=location,
                        message="Mask policies must set an explicit non-empty 'to' principal list.",
                    )
                )
            if rules.require_mask_except and not (policy.exceptions or []):
                violations.append(
                    LintViolation(
                        rule_id="mask.except_required",
                        severity="error",
                        location=location,
                        message="Mask policies should set an explicit non-empty 'except' principal list.",
                    )
                )
        if (
            rules.fail_on_schema_grants
            and isinstance(policy, GrantPolicyConfig)
            and policy.for_securable_type == SecurableType.SCHEMA
        ):
            violations.append(
                LintViolation(
                    rule_id="grant.schema_scope",
                    severity=rules.schema_grant_severity,
                    location=location,
                    message=(
                        "Schema-level grant policy detected. Prefer table-level grants for sensitive "
                        "domains to reduce exposure windows."
                    ),
                )
            )

    violations.sort(key=lambda v: (v.severity, v.rule_id, v.location, v.message))
    return LintResult(violations=tuple(violations))
