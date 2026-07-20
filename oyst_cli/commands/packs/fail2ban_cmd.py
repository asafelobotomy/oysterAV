"""fail2ban intrusion prevention CLI commands."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.output import emit
from oyst_core.packs.fail2ban import Fail2banPack


@click.group("fail2ban")
def fail2ban_group() -> None:
    """fail2ban intrusion prevention."""


@fail2ban_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def fail2ban_status(json_mode: bool) -> None:
    """Service and jail list (upstream: fail2ban-client status)."""
    emit(Fail2banPack().service_status(), json_mode=json_mode)


@fail2ban_group.command("jail")
@click.argument("name")
@click.option("--json", "json_mode", is_flag=True)
def fail2ban_jail(name: str, json_mode: bool) -> None:
    """Jail detail (upstream: fail2ban-client status <jail>)."""
    emit(Fail2banPack().jail_status(name), json_mode=json_mode)


@fail2ban_group.command("banned")
@click.option("--json", "json_mode", is_flag=True)
def fail2ban_banned(json_mode: bool) -> None:
    """List banned IPs per jail (upstream: fail2ban-client banned)."""
    emit(Fail2banPack().banned(), json_mode=json_mode)


@fail2ban_group.command(
    "unban",
    epilog="""
Examples:
  oyst-cli fail2ban unban 192.0.2.1 --confirm --json
  oyst-cli fail2ban unban 192.0.2.1 --jail sshd --confirm --ignore --json
""",
)
@click.argument("ip")
@click.option("--jail")
@click.option("--ignore", is_flag=True, help="Add IP to jail ignore list after unban")
@click.option("--persist", is_flag=True, help="Write ignoreip to jail.d drop-in")
@click.option("--confirm", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def fail2ban_unban(
    ip: str,
    jail: str | None,
    ignore: bool,
    persist: bool,
    confirm: bool,
    json_mode: bool,
) -> None:
    """Unban an IP (upstream: fail2ban-client unban / set jail unbanip)."""
    require_confirm(confirm, message="--confirm required to unban an IP")
    ok, msg = Fail2banPack().unban(ip, jail=jail, ignore=ignore, persist=persist)
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@fail2ban_group.group("jail-control")
def fail2ban_jail_control() -> None:
    """Enable or disable individual jails."""


@fail2ban_jail_control.command("enable")
@click.argument("name")
@click.option("--confirm", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def fail2ban_jail_enable(name: str, confirm: bool, json_mode: bool) -> None:
    """Start a jail."""
    require_confirm(confirm, message="--confirm required to enable a jail")
    ok, msg = Fail2banPack().set_jail_enabled(name, enabled=True)
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@fail2ban_jail_control.command("disable")
@click.argument("name")
@click.option("--confirm", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def fail2ban_jail_disable(name: str, confirm: bool, json_mode: bool) -> None:
    """Stop a jail."""
    require_confirm(confirm, message="--confirm required to disable a jail")
    ok, msg = Fail2banPack().set_jail_enabled(name, enabled=False)
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@fail2ban_group.command("reload")
@click.option("--unban", is_flag=True, help="Also unban all IPs on reload")
@click.option("--confirm", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def fail2ban_reload(unban: bool, confirm: bool, json_mode: bool) -> None:
    """Reload fail2ban configuration."""
    if unban:
        require_confirm(confirm, message="--confirm required for reload --unban")
    ok, msg = Fail2banPack().reload(unban=unban)
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)
