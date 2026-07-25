"""Adversarial corpora for privileged input validators."""

from __future__ import annotations

import pytest

from oyst_core.privileged.validators import (
    validate_cidr,
    validate_ip,
    validate_jail,
    validate_monitor_mode,
    validate_port,
    validate_rich_rule,
    validate_service_name,
    validate_zone,
)

pytestmark = pytest.mark.security

_META = (";", "|", "&", "$", "`", "\n", "\r", '"', "'")


@pytest.mark.parametrize(
    "rule",
    [
        "rule family=ipv4 port port=22 protocol=tcp accept",
        "rule family=ipv6 port port=443 protocol=tcp reject",
        "rule service name=ssh drop",
        "rule source address=192.0.2.1 port port=80 protocol=tcp accept",
        "rule family=ipv4 source address=10.0.0.0/8 service name=http accept",
    ],
)
def test_validate_rich_rule_accepts_subset(rule: str) -> None:
    assert validate_rich_rule(rule) == rule


@pytest.mark.parametrize(
    "rule",
    [
        "",
        "x" * 513,
        "rule accept",
        "rule port port=22 protocol=tcp",  # missing action
        "rule port=22 protocol=tcp accept",  # wrong grammar
        "rule family=ipv4 accept",
        "rule port port=22 accept",  # missing proto
        "rule service name=ssh accept; rm -rf /",
        "rule service name=ssh accept | cat",
        "rule service name=ssh accept && true",
        "rule service name=ssh accept$(id)",
        "rule service name=ssh accept`id`",
        'rule service name=ssh accept"',
        "rule service name=ssh accept'",
        "rule service name=ssh accept\naccept",
        "rule family=ipv4 port port=99999 protocol=tcp accept",
        "rule source address=not-an-ip port port=22 protocol=tcp accept",
        "rule service name=../../etc/passwd accept",
        "rule service name=ssh (accept)",
    ],
)
def test_validate_rich_rule_rejects(rule: str) -> None:
    with pytest.raises(ValueError):
        validate_rich_rule(rule)


@pytest.mark.parametrize(
    "value",
    ["1.2.3.4;id", "127.0.0.1/extra", "not-an-ip", "", "1.2.3.4|1.2.3.5"],
)
def test_validate_ip_rejects(value: str) -> None:
    with pytest.raises(ValueError):
        validate_ip(value)


def test_validate_ip_accepts() -> None:
    assert validate_ip("192.0.2.1") == "192.0.2.1"


@pytest.mark.parametrize(
    "value",
    ["10.0.0.0/8;id", "not-a-cidr", "10.0.0.0/99", ""],
)
def test_validate_cidr_rejects(value: str) -> None:
    with pytest.raises(ValueError):
        validate_cidr(value)


def test_validate_cidr_accepts() -> None:
    assert "/" in validate_cidr("10.0.0.0/8")


@pytest.mark.parametrize("value", ["0", "65536", "-1", "22;id", "abc", ""])
def test_validate_port_rejects(value: str) -> None:
    with pytest.raises(ValueError):
        validate_port(value)


def test_validate_port_accepts() -> None:
    assert validate_port("22") == "22"


@pytest.mark.parametrize(
    "name",
    ["", "a;rm", "jail|x", "x&y", "a$b", "a`b", "a\nb", "../jail", "x" * 65],
)
def test_validate_jail_rejects(name: str) -> None:
    with pytest.raises(ValueError):
        validate_jail(name)


@pytest.mark.parametrize(
    "name",
    ["", "z;id", "z|x", "public space", "../zone", "x" * 65],
)
def test_validate_zone_rejects(name: str) -> None:
    with pytest.raises(ValueError):
        validate_zone(name)


@pytest.mark.parametrize(
    "name",
    ["", "ssh;id", "http|curl", "svc&x", "a$b", "a`b", "../svc", "x" * 65],
)
def test_validate_service_name_rejects(name: str) -> None:
    with pytest.raises(ValueError):
        validate_service_name(name)


@pytest.mark.parametrize(
    "mode",
    [
        "",
        "relative/path",
        "/tmp/evil;id",
        "/tmp/evil|cat",
        "/tmp/evil&true",
        "/tmp/evil$(id)",
        "/tmp/evil`id`",
        '/tmp/evil"',
        "/tmp/../etc/passwd",
        "users;/bin/sh",
    ],
)
def test_validate_monitor_mode_rejects(mode: str) -> None:
    with pytest.raises(ValueError):
        validate_monitor_mode(mode)


def test_validate_monitor_mode_accepts() -> None:
    assert validate_monitor_mode("users") == "users"
    assert validate_monitor_mode("/home/alice,/var/tmp/safe") == "/home/alice,/var/tmp/safe"


@pytest.mark.parametrize("ch", _META)
def test_validate_service_name_rejects_each_metachar(ch: str) -> None:
    with pytest.raises(ValueError):
        validate_service_name(f"ssh{ch}x")
