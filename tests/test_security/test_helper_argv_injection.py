"""Helper argv builders must reject injection / non-allowlisted commands."""

from __future__ import annotations

import pytest

from oyst_core.privileged.helper_firewall import (
    _build_firewall_argv,
    _build_firewalld_argv,
    _build_ufw_argv,
)
from oyst_core.privileged.helper_validate import _validate_run_argv

pytestmark = pytest.mark.security

_SHELL_META_TOKENS = {";", "|", "&", "$", "`", "&&", "||", "$(id)", "`id`"}


def _assert_safe_argv(argv: list[str], *, heads: set[str]) -> None:
    assert argv
    assert argv[0] in heads
    for token in argv:
        assert token not in _SHELL_META_TOKENS
        assert ";" not in token
        assert "|" not in token or token.startswith("--")  # firewall-cmd flags use =
        assert "\n" not in token
        assert "$( " not in token


@pytest.mark.parametrize(
    "argv",
    [
        ["allow", "--port", "22", "--proto", "tcp;id"],
        ["allow", "--port", "22;rm", "--proto", "tcp"],
        ["allow", "--from", "1.2.3.4;id", "--port", "22"],
        ["allow", "--port", "22", "--proto", "tcp", ";rm"],
        ["default", "incoming", "deny;id"],
        ["enable", ";id"],
        ["bash", "-c", "id"],
        ["allow"],
    ],
)
def test_build_ufw_argv_rejects(argv: list[str]) -> None:
    with pytest.raises(ValueError):
        _build_ufw_argv(argv)


def test_build_ufw_argv_safe_shape() -> None:
    argv = _build_ufw_argv(["allow", "--port", "22", "--proto", "tcp"])
    _assert_safe_argv(argv, heads={"ufw"})
    assert argv == ["ufw", "allow", "22/tcp"]


@pytest.mark.parametrize(
    "argv",
    [
        ["add-port", "22/tcp;id"],
        ["add-service", "ssh;id"],
        ["add-rich-rule", "rule", "service", "name=ssh", "accept;id"],
        ["add-port", "22/tcp", "--zone", "public;id"],
        ["disable", ";rm"],
        ["nft", "flush", "ruleset"],
    ],
)
def test_build_firewalld_argv_rejects(argv: list[str]) -> None:
    with pytest.raises(ValueError):
        _build_firewalld_argv(argv)


def test_build_firewalld_argv_safe_shape() -> None:
    argv = _build_firewalld_argv(["add-port", "443/tcp", "--zone", "public"])
    assert argv[0] == "firewall-cmd"
    assert all(";" not in t and "\n" not in t for t in argv)


def test_build_firewall_argv_rejects_unknown_backend() -> None:
    with pytest.raises(ValueError, match="unknown firewall backend"):
        _build_firewall_argv(["nft", "list", "ruleset"])


def test_build_firewall_argv_dispatches() -> None:
    ufw = _build_firewall_argv(["ufw", "reload"])
    assert ufw[0] == "ufw"
    fwd = _build_firewall_argv(["firewalld", "reload"])
    assert fwd[0] == "firewall-cmd"


@pytest.mark.parametrize(
    "argv",
    [
        ["nft", "list", "ruleset"],
        ["bash", "-c", "id"],
        ["/bin/sh", "-c", "id"],
        ["pacman", "-Sy", "--noconfirm", "../evil"],
        ["pacman", "-Sy", "--noconfirm", "pkg;id"],
        ["dnf", "install", "-y", "pkg|x"],
        ["curl", "http://evil"],
        [],
    ],
)
def test_validate_run_argv_rejects(argv: list[str]) -> None:
    with pytest.raises(ValueError):
        _validate_run_argv(argv)


def test_validate_run_argv_allows_pacman_shape() -> None:
    assert _validate_run_argv(["pacman", "-Sy", "--noconfirm", "ufw"]) == [
        "pacman",
        "-Sy",
        "--noconfirm",
        "ufw",
    ]
