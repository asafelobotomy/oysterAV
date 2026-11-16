"""The uq/ folder: every declared command is a real oyst-cli invocation.

uQ runs these argv lists itself (no shell), appending only arguments that match
each declared pattern. These tests keep the manifests in step with the CLI:
each argv must parse, with sample arguments, to an existing command, and the
patterns must accept the samples and refuse anything that could become an
option. `uqctl integrations check uq/` checks the rest (uQ's own rules).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import click
import pytest

from oyst_cli.main import cli

ROOT = Path(__file__).resolve().parents[2]
UQ = ROOT / "uq"
WIDGET = UQ / "widgets" / "oysterav" / "widget.toml"
PAGE = UQ / "pages" / "oysterav-security" / "page.toml"

# A value each declared argument must accept, by argument name.
SAMPLES = {
    "folder": "/home/user/Downloads/some folder",
    "entry": "12",
    "frequency": "weekly",
    "time": "02:30",
}

# Commands that may change something must ask first in Settings.
DESTRUCTIVE = {"quarantine-restore", "quarantine-delete", "schedule-disable", "rootkit-check"}


def _manifest(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _commands() -> list[tuple[str, dict[str, Any]]]:
    out = [("widget", c) for c in _manifest(WIDGET).get("command", [])]
    out += [("page", c) for c in _manifest(PAGE).get("command", [])]
    return out


def _pattern(spec: dict[str, Any]) -> re.Pattern[str]:
    pattern = str(spec["pattern"])
    assert pattern.startswith("^") and pattern.endswith("$"), pattern
    return re.compile(pattern)


def _resolve(argv: list[str]) -> click.Command:
    """Parse argv as oyst-cli would, without running anything: subcommand names, then the
    leaf command's own options and arguments (a bad option raises a click error)."""
    cmd: click.Command = cli
    args = list(argv)
    while isinstance(cmd, click.Group):
        assert args, f"{argv}: stops at group {cmd.name}"
        sub = cmd.commands.get(args[0])
        assert sub is not None, f"{argv}: no command {args[0]}"
        cmd, args = sub, args[1:]
    with cmd.make_context(cmd.name or "oyst-cli", args) as _ctx:
        pass
    return cmd


def test_manifests_parse_and_match_ids() -> None:
    widget = _manifest(WIDGET)
    page = _manifest(PAGE)
    assert widget["id"] == WIDGET.parent.name and widget["slot"] == "quick"
    assert page["id"] == PAGE.parent.name
    assert widget["uq_api"] == 1 and page["uq_api"] == 1
    assert (WIDGET.parent / widget["qml"]).is_file()
    assert (PAGE.parent / page["qml"]).is_file()
    ids = [c["id"] for _, c in _commands() if _ == "page"]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize(
    ("where", "command"), _commands(), ids=lambda v: str(v) if isinstance(v, str) else v["id"]
)
def test_command_is_a_real_oyst_cli_call(where: str, command: dict[str, Any]) -> None:
    argv = list(command["argv"])
    assert argv[0] == "/usr/bin/oyst-cli"
    assert "--json" in argv, "uQ reads every command's output as JSON"
    assert command["output"] == "json"
    samples = [SAMPLES[a["name"]] for a in command.get("args", [])]
    for spec, sample in zip(command.get("args", []), samples, strict=True):
        assert _pattern(spec).fullmatch(sample), (spec, sample)
    leaf = _resolve(argv[1:] + samples)
    assert leaf.callback is not None
    if where == "widget":
        assert "confirm" not in command
    if command["id"] in DESTRUCTIVE:
        assert command.get("confirm"), f"{command['id']} must ask first"


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("folder", "-rf"),
        ("folder", "--quarantine"),
        ("folder", "relative/path"),
        ("folder", "/tmp/a\nb"),
        ("folder", ""),
        ("entry", "-1"),
        ("entry", "0"),
        ("entry", "1 2"),
        ("entry", "1234567890"),
        ("frequency", "--confirm"),
        ("frequency", "custom"),
        ("time", "24:00"),
        ("time", "2:30"),
        ("time", "--time"),
    ],
)
def test_argument_patterns_refuse_options_and_junk(name: str, bad: str) -> None:
    specs = [a for _, c in _commands() for a in c.get("args", []) if a["name"] == name]
    assert specs, name
    for spec in specs:
        assert not _pattern(spec).fullmatch(bad), (spec, bad)


def test_status_summary_is_what_both_use() -> None:
    widget = {c["id"]: c for c in _manifest(WIDGET)["command"]}
    page = {c["id"]: c for c in _manifest(PAGE)["command"]}
    assert widget["summary"]["argv"] == page["summary"]["argv"]
    assert widget["summary"]["argv"][1:3] == ["status", "summary"]


def test_qml_shows_text_only_through_uq_components() -> None:
    banned = re.compile(
        r"(^|[^A-Za-z0-9_.])([A-Za-z_][A-Za-z0-9_]*\.)*(TextEdit|TextInput|Text|Label)\s*\{"
    )
    for qml in UQ.rglob("*.qml"):
        text = qml.read_text(encoding="utf-8")
        assert not banned.search(text), qml
        assert "Qt.createQmlObject" not in text, qml
        assert "Quickshell" not in text, qml


@pytest.mark.parametrize(
    "path",
    [
        "packaging/arch/PKGBUILD",
        "packaging/arch/PKGBUILD.in",
        "packaging/rpm/oysterav.spec",
        "packaging/debian/oysterav.install",
        "scripts/build_native_packages.sh",
    ],
)
def test_packages_install_the_uq_folder(path: str) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    assert "uq/widgets/oysterav/" in text, path
    assert "uq/pages/oysterav-security/" in text, path
    assert "/uq/shell/widgets/oysterav" in text, path
    assert "/uq/settings/pages/oysterav-security" in text, path
