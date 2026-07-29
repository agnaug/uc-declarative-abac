from __future__ import annotations

import pytest

from uc_declarative_abac.cli.parser import parse_cli_args


def test_parser_routes_plan_to_dry_run():
    namespace = parse_cli_args(
        ["plan", "--config-dir", "cfg", "--warehouse-id", "wh"],
    )
    assert namespace.command == "plan"


def test_parser_routes_apply_to_execute():
    namespace = parse_cli_args(
        ["apply", "--config-dir", "cfg", "--warehouse-id", "wh"],
    )
    assert namespace.command == "apply"


def test_parser_legacy_dry_run_maps_to_plan():
    namespace = parse_cli_args(
        ["--config-dir", "cfg", "--warehouse-id", "wh", "--dry-run"],
    )
    assert namespace.command == "plan"
    assert namespace.legacy is True


def test_parser_legacy_without_dry_run_maps_to_apply():
    namespace = parse_cli_args(
        ["--config-dir", "cfg", "--warehouse-id", "wh"],
    )
    assert namespace.command == "apply"
    assert namespace.legacy is True


def test_cli_reports_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        parse_cli_args(["--version"])
    assert exc_info.value.code == 0


def test_parser_accepts_resource_output_flag():
    namespace = parse_cli_args(
        ["plan", "--config-dir", "cfg", "--warehouse-id", "wh", "--output", "resource"],
    )
    assert namespace.output == "resource"


def test_parser_accepts_no_color_flag():
    namespace = parse_cli_args(
        ["plan", "--config-dir", "cfg", "--warehouse-id", "wh", "--no-color"],
    )
    assert namespace.no_color is True


def test_parser_accepts_json_output_flag():
    namespace = parse_cli_args(
        ["plan", "--config-dir", "cfg", "--warehouse-id", "wh", "--output", "json"],
    )
    assert namespace.output == "json"


def test_parser_routes_lint_command():
    namespace = parse_cli_args(["lint", "--config-dir", "cfg"])
    assert namespace.command == "lint"
    assert namespace.config_dir.name == "cfg"
