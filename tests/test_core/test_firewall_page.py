"""The Firewall tab's backend: the overview read, the plans, and what each change hands on."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oyst_core.packs import firewall_page as fp
from oyst_core.packs import firewall_view as fv
from oyst_core.privileged.helper_firewall import _build_ufw_argv
from oyst_core.privileged.helper_firewall_batch import parse_ufw_batch_rules
from oyst_core.privileged.validators import port_range_covers, validate_port_range

USER_RULES = """\
*filter
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -j ACCEPT

### tuple ### allow udp 1714:1764 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p udp -m multiport --dports 1714:1764 -j ACCEPT

### tuple ### deny tcp 3306 0.0.0.0/0 any 192.168.1.0/24 in
-A ufw-user-input -p tcp --dport 3306 -s 192.168.1.0/24 -j DROP

### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_eth0
-A ufw-user-input -i eth0 -p tcp --dport 80 -j ACCEPT

### END RULES ###
"""
USER6_RULES = """\
### tuple ### allow tcp 22 ::/0 any ::/0 in
### tuple ### allow udp 1714:1764 ::/0 any ::/0 in
"""
DEFAULTS = """\
IPV6=yes
DEFAULT_INPUT_POLICY="DROP"
DEFAULT_OUTPUT_POLICY="ACCEPT"
DEFAULT_FORWARD_POLICY="DROP"
"""
ZONES = """\
block
  target: %%REJECT%%
  services:
  ports:

public (default, active)
  target: default
  interfaces: eth0 wlan0
  sources:
  services: dhcpv6-client ssh
  ports: 8080/tcp 6000-6010/udp
  protocols:

trusted
  target: ACCEPT
  services:
"""


class _Res:
    def __init__(self, rc: int = 0, out: str = "") -> None:
        self.returncode = rc
        self.stdout = out
        self.stderr = ""


@pytest.fixture
def ufw_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """UFW on, run as a user (``ufw status`` needs root), rules read from its files."""
    (tmp_path / "user.rules").write_text(USER_RULES)
    (tmp_path / "user6.rules").write_text(USER6_RULES)
    (tmp_path / "ufw").write_text(DEFAULTS)
    monkeypatch.setattr(fv, "_UFW_RULES", (tmp_path / "user.rules", tmp_path / "user6.rules"))
    monkeypatch.setattr(fv, "_UFW_DEFAULTS", tmp_path / "ufw")

    def detect(_self: Any) -> dict[str, object]:
        return {
            "active": "ufw",
            "ufw": True,
            "firewalld": False,
            "conflict": False,
            "version": "0.36.2",
        }

    def run(argv: list[str], timeout: int = 0) -> _Res:
        if argv[0] == "ufw":
            return _Res(1, "ERROR: You need to be root to run this script")
        return _Res(3, "inactive")

    monkeypatch.setattr(fv.FirewallPack, "detect", detect)
    monkeypatch.setattr(fv, "run_command", run)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    return tmp_path


def test_overview_reads_ufw_without_root(ufw_host: Path) -> None:
    view = fv.firewall_overview()
    assert view["backend"] == "ufw" and view["on"] and not view["ssh_in_use"]
    assert view["defaults"] == {"incoming": "deny", "outgoing": "allow", "routed": "deny"}
    rules = {(r["action"], r["port"], r["proto"], r["source"]): r for r in view["rules"]}
    ssh = rules[("allow", "22", "tcp", "anywhere")]
    assert ssh["removable"] and ssh["editable"] and not ssh["ipv6_only"]
    kde = rules[("allow", "1714:1764", "udp", "anywhere")]
    assert kde["removable"], "a port range can be removed exactly"
    assert rules[("deny", "3306", "tcp", "192.168.1.0/24")]["editable"]
    assert not rules[("allow", "80", "tcp", "anywhere")]["removable"], (
        "interface rules stay as they are"
    )


def test_ssh_in_use_follows_the_server(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr(
        fv,
        "run_command",
        lambda argv, timeout=0: _Res(0, "active" if argv[2] == "sshd.service" else "inactive"),
    )
    assert fv.ssh_in_use()
    monkeypatch.setattr(fv, "run_command", lambda argv, timeout=0: _Res(3, "inactive"))
    assert not fv.ssh_in_use()
    monkeypatch.setenv("SSH_CONNECTION", "10.0.0.2 5000 10.0.0.1 22")
    assert fv.ssh_in_use()


def test_parse_zones_puts_the_default_first() -> None:
    zones = fv.parse_zones(ZONES, "public")
    assert [z["name"] for z in zones] == ["public", "block", "trusted"]
    public = zones[0]
    assert public["default"] and public["active"]
    assert public["interfaces"] == ["eth0", "wlan0"]
    assert public["services"] == ["dhcpv6-client", "ssh"]
    assert public["ports"] == ["8080/tcp", "6000-6010/udp"]
    assert zones[1]["target"] == "%%REJECT%%"


def test_ufw_defaults_missing_file(tmp_path: Path) -> None:
    assert fv.ufw_defaults(tmp_path / "nope") == {}


# ---- plans and changes ---------------------------------------------------------------------------


def _view(**over: Any) -> dict[str, Any]:
    view: dict[str, Any] = {
        "ok": True,
        "backend": "ufw",
        "on": True,
        "active": "ufw",
        "conflict": False,
        "installed": {"ufw": True, "firewalld": False},
        "recommended": "ufw",
        "ssh_in_use": False,
        "defaults": {"incoming": "deny", "outgoing": "allow", "routed": "deny"},
        "rules": [
            {
                "action": "allow",
                "port": "22",
                "proto": "tcp",
                "direction": "in",
                "source": "anywhere",
                "removable": True,
                "editable": True,
            },
            {
                "action": "allow",
                "port": "8080",
                "proto": "tcp",
                "direction": "in",
                "source": "anywhere",
                "removable": True,
                "editable": True,
            },
        ],
        "rules_readable": True,
        "zones": [],
        "version": "0.36.2",
    }
    view.update(over)
    return view


@pytest.fixture
def batches(monkeypatch: pytest.MonkeyPatch) -> list[tuple[list[dict[str, Any]], bool]]:
    """Every ufw_batch call: (rules, force_lockout). Nothing reaches pkexec."""
    calls: list[tuple[list[dict[str, Any]], bool]] = []

    def fake(
        rules: list[dict[str, Any]], *, force_lockout: bool = False, dry_run: bool = False
    ) -> dict[str, Any]:
        parse_ufw_batch_rules(
            [f"--rule={__import__('json').dumps(r)}" for r in rules]
        )  # the helper accepts them
        calls.append((rules, force_lockout))
        return {"ok": True, "message": "ok", "steps": []}

    import oyst_core.packs.firewall_batch as fb

    monkeypatch.setattr(fb, "ufw_batch", fake)
    return calls


def _use(monkeypatch: pytest.MonkeyPatch, **over: Any) -> None:
    monkeypatch.setattr(fp, "firewall_overview", lambda: _view(**over))


def test_rule_add_plan_and_run(monkeypatch: pytest.MonkeyPatch, batches: list[Any]) -> None:
    _use(monkeypatch)
    plan = fp.rule_add("allow", "1714:1764", "udp", "anywhere", dry_run=True)
    assert not plan["would_refuse"]
    assert plan["changes"][0]["label"] == "Allow 1714-1764/udp from anywhere"
    assert batches == []
    out = fp.rule_add("allow", "1714:1764", "udp", "anywhere")
    assert out == {"ok": True, "message": "Rule added."}
    assert batches == [([{"action": "allow", "port": "1714:1764", "proto": "udp"}], True)]


@pytest.mark.parametrize(
    ("args", "why"),
    [
        (("allow", "22", "tcp", "anywhere"), "already there"),
        (("allow", "70000", "tcp", "anywhere"), "out of range"),
        (("allow", "90:80", "tcp", "anywhere"), "low to high"),
        (("reject", "80", "tcp", "anywhere"), "allow, block or limit"),
        (("allow", "80", "tcp", "not-an-ip"), "invalid IP"),
    ],
)
def test_rule_add_refuses(
    monkeypatch: pytest.MonkeyPatch, batches: list[Any], args: tuple[str, ...], why: str
) -> None:
    _use(monkeypatch)
    plan = fp.rule_add(*args, dry_run=True)
    assert plan["would_refuse"] and why in plan["reason"]
    assert not fp.rule_add(*args)["ok"]
    assert batches == []


def test_rules_need_ufw_on(monkeypatch: pytest.MonkeyPatch, batches: list[Any]) -> None:
    _use(monkeypatch, on=False, active="none")
    assert (
        "Turn the firewall on"
        in fp.rule_add("allow", "80", "tcp", "anywhere", dry_run=True)["reason"]
    )
    _use(monkeypatch, backend="firewalld", active="firewalld")
    assert (
        "UFW isn't the firewall"
        in fp.rule_add("allow", "80", "tcp", "anywhere", dry_run=True)["reason"]
    )


def test_ssh_is_guarded_only_while_ssh_runs(
    monkeypatch: pytest.MonkeyPatch, batches: list[Any]
) -> None:
    _use(monkeypatch, ssh_in_use=True)
    assert fp.rule_remove("allow", "22", "tcp", "anywhere", dry_run=True)["would_refuse"]
    assert fp.rule_add("deny", "20:30", "tcp", "anywhere", dry_run=True)["would_refuse"]
    assert fp.rule_change(
        ["allow", "22", "tcp", "anywhere"], ["allow", "2222", "tcp", "anywhere"], dry_run=True
    )["would_refuse"]
    assert not fp.rule_change(
        ["allow", "22", "tcp", "anywhere"], ["limit", "22", "tcp", "anywhere"], dry_run=True
    )["would_refuse"]
    _use(monkeypatch, ssh_in_use=False)
    assert not fp.rule_remove("allow", "22", "tcp", "anywhere", dry_run=True)["would_refuse"]
    fp.rule_remove("allow", "22", "tcp", "anywhere")
    assert batches[-1] == (
        [{"action": "delete", "rule_action": "allow", "port": "22", "proto": "tcp"}],
        True,
    )


def test_rule_change_adds_then_removes_in_one_prompt(
    monkeypatch: pytest.MonkeyPatch, batches: list[Any]
) -> None:
    _use(monkeypatch)
    old = ["allow", "8080", "tcp", "anywhere"]
    new = ["allow", "8080", "tcp", "192.168.1.0/24"]
    plan = fp.rule_change(old, new, dry_run=True)
    assert [c["group"] for c in plan["changes"]] == ["Add", "Remove"]
    assert fp.rule_change(old, new)["ok"]
    rules, _ = batches[-1]
    assert rules == [
        {"action": "allow", "port": "8080", "proto": "tcp", "from_addr": "192.168.1.0/24"},
        {"action": "delete", "rule_action": "allow", "port": "8080", "proto": "tcp"},
    ]
    assert fp.rule_change(old, old, dry_run=True)["reason"] == "Nothing changed."
    gone = ["deny", "9999", "tcp", "anywhere"]
    assert "isn't in the list" in fp.rule_change(gone, new, dry_run=True)["reason"]


def test_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch)
    calls: list[tuple[str, str, bool]] = []

    class Ops:
        def ufw_default(self, direction: str, policy: str, *, force_lockout: bool = False) -> Any:
            calls.append((direction, policy, force_lockout))
            return type("R", (), {"ok": True, "message": "ok"})()

        def _ssh_allowed(self, _backend: str) -> bool:
            return False

    import oyst_core.packs.firewall_ops as fo

    monkeypatch.setattr(fo, "FirewallOps", Ops)
    assert fp.policy("incoming", "deny", dry_run=True)["would_refuse"]
    plan = fp.policy("outgoing", "deny", dry_run=True)
    assert plan["changes"][0]["detail"].startswith("Now: allow")
    assert fp.policy("outgoing", "deny")["ok"]
    assert calls == [("outgoing", "deny", True)]
    _use(monkeypatch, ssh_in_use=True, defaults={"incoming": "allow"})
    assert fp.policy("incoming", "deny", dry_run=True)["reason"] == fp.SSH_REASON


def test_power(monkeypatch: pytest.MonkeyPatch) -> None:
    import oyst_core.packs.firewall_ensure as fe

    seen: list[tuple[str, bool]] = []
    result = type("R", (), {"ok": True, "message": "ok"})()
    monkeypatch.setattr(
        fe,
        "ensure_firewall_enabled",
        lambda *, force_lockout=False: seen.append(("on", force_lockout)) or result,
    )
    monkeypatch.setattr(
        fe,
        "set_managed_enabled",
        lambda on, *, force_lockout=False: seen.append(("off", force_lockout)) or result,
    )
    _use(monkeypatch)
    assert fp.power("on", dry_run=True)["reason"] == "The firewall is already on."
    assert not fp.power("off", dry_run=True)["would_refuse"]
    assert fp.power("off") == {"ok": True, "message": "The firewall is off."}
    _use(monkeypatch, on=False, active="none", ssh_in_use=True)
    plan = fp.power("on", dry_run=True)
    assert any("SSH" in c["label"] for c in plan["changes"])
    fp.power("on")
    assert seen == [("off", True), ("on", False)]
    _use(monkeypatch, backend="none", on=False, active="none")
    assert "No firewall program" in fp.power("on", dry_run=True)["reason"]
    _use(monkeypatch, conflict=True)
    assert fp.power("off", dry_run=True)["would_refuse"]


def test_zone_open(monkeypatch: pytest.MonkeyPatch) -> None:
    zone = {
        "name": "public",
        "default": True,
        "active": True,
        "services": ["ssh"],
        "ports": ["8080/tcp"],
    }
    _use(monkeypatch, backend="firewalld", active="firewalld", zones=[zone], ssh_in_use=True)
    assert (
        "already open" in fp.zone_open("port", "add", "public", "8080/tcp", dry_run=True)["reason"]
    )
    assert "protocol" in fp.zone_open("port", "add", "public", "8080", dry_run=True)["reason"]
    assert "no zone" in fp.zone_open("service", "add", "work", "http", dry_run=True)["reason"]
    assert (
        fp.zone_open("service", "remove", "public", "ssh", dry_run=True)["reason"] == fp.SSH_REASON
    )
    plan = fp.zone_open("service", "add", "public", "kdeconnect", dry_run=True)
    assert plan["changes"][0]["label"] == "Open kdeconnect"


# ---- ranges reach ufw the way it wants them ------------------------------------------------------


def test_port_ranges() -> None:
    assert validate_port_range("1714:1764") == "1714:1764"
    assert validate_port_range(" 22 ") == "22"
    for bad in ("1764:1714", "22:22", "0:5", "1:70000", "a:b", "1:2:3", "22/tcp"):
        with pytest.raises(ValueError):
            validate_port_range(bad)
    assert port_range_covers("20:30", 22) and port_range_covers("22", 22)
    assert not port_range_covers("23:30", 22) and not port_range_covers("x", 22)


def test_helper_builds_ranges() -> None:
    assert _build_ufw_argv(["allow", "--port", "1714:1764", "--proto", "udp"]) == [
        "ufw",
        "allow",
        "1714:1764/udp",
    ]
    assert _build_ufw_argv(
        [
            "delete",
            "--port",
            "1714:1764",
            "--proto",
            "udp",
            "--from",
            "10.0.0.0/8",
            "--rule-action",
            "deny",
        ]
    ) == [
        "ufw",
        "delete",
        "deny",
        "from",
        "10.0.0.0/8",
        "proto",
        "udp",
        "to",
        "any",
        "port",
        "1714:1764",
    ]
    with pytest.raises(ValueError):
        _build_ufw_argv(["allow", "--port", "1714:1764"])
