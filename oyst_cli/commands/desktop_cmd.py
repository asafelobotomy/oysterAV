"""Desktop integration CLI (autostart / icons / launcher / tray status)."""

from __future__ import annotations

import click

from oyst_cli.output import emit
from oyst_core.desktop_icons import (
    ensure_desktop_integration,
    install_user_icons,
    install_user_launcher,
    remove_user_launcher,
)
from oyst_core.desktop_util import (
    autostart_status,
    install_autostart,
    remove_autostart,
)


@click.group("desktop")
def desktop_group() -> None:
    """GUI desktop integration (icons, launcher, autostart, tray probe)."""


@desktop_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def desktop_status(json_mode: bool) -> None:
    """Show UI config, icons/launcher, autostart file, and tray availability."""
    data = autostart_status()
    if json_mode:
        emit(data, json_mode=True)
        return
    click.echo(f"Run at startup: {data.get('run_at_startup')}")
    click.echo(f"Start minimized: {data.get('start_minimized')}")
    click.echo(f"Minimize to tray: {data.get('minimize_to_tray')}")
    click.echo(f"Icon name: {data.get('icon_name')}")
    click.echo(f"User icons installed: {data.get('user_icons_installed')}")
    click.echo(f"Launcher: {data.get('launcher_path')}")
    click.echo(f"Launcher present: {data.get('launcher_present')}")
    click.echo(f"Autostart file: {data.get('autostart_path')}")
    click.echo(f"Autostart present: {data.get('autostart_present')}")
    click.echo(f"Exec: {data.get('exec')}")
    click.echo(f"Flatpak: {data.get('flatpak')}")
    tray_raw = data.get("tray")
    tray = tray_raw if isinstance(tray_raw, dict) else {}
    if tray.get("available"):
        click.echo(f"Tray library: {tray.get('library')} {tray.get('version')}")
    else:
        click.echo(f"Tray library: missing — {tray.get('hint', '')}")


@desktop_group.command("install")
@click.option("--json", "json_mode", is_flag=True)
def desktop_install(json_mode: bool) -> None:
    """Install user icons (hicolor) and applications-menu launcher."""
    result = ensure_desktop_integration()
    if json_mode:
        emit(result, json_mode=True)
        return
    click.echo(str(result.get("message", "ok")))
    icons = result.get("icons") if isinstance(result.get("icons"), dict) else {}
    launcher = result.get("launcher") if isinstance(result.get("launcher"), dict) else {}
    if icons.get("path"):
        click.echo(f"Icons: {icons['path']}")
    if launcher.get("path"):
        click.echo(f"Launcher: {launcher['path']}")
    if not result.get("ok"):
        raise SystemExit(2)


@desktop_group.command("install-icons")
@click.option("--json", "json_mode", is_flag=True)
def desktop_install_icons(json_mode: bool) -> None:
    """Install oysterav theme icons into ~/.local/share/icons/hicolor."""
    result = install_user_icons()
    if json_mode:
        emit(result, json_mode=True)
        return
    click.echo(str(result.get("message", "ok")))
    if not result.get("ok"):
        raise SystemExit(2)


@desktop_group.command("install-launcher")
@click.option("--json", "json_mode", is_flag=True)
def desktop_install_launcher(json_mode: bool) -> None:
    """Install ~/.local/share/applications launcher (.desktop)."""
    result = install_user_launcher()
    if json_mode:
        emit(result, json_mode=True)
        return
    click.echo(str(result.get("message", "ok")))
    if not result.get("ok"):
        raise SystemExit(2)


@desktop_group.command("remove-launcher")
@click.option("--json", "json_mode", is_flag=True)
def desktop_remove_launcher(json_mode: bool) -> None:
    """Remove the user applications-menu launcher (does not remove icons)."""
    result = remove_user_launcher()
    if json_mode:
        emit(result, json_mode=True)
        return
    click.echo(str(result.get("message", "ok")))
    if not result.get("ok"):
        raise SystemExit(2)


@desktop_group.command("install-autostart")
@click.option("--json", "json_mode", is_flag=True)
@click.option(
    "--minimized/--no-minimized",
    default=None,
    help="Override ui.start_minimized for the Exec line",
)
def desktop_install_autostart(json_mode: bool, minimized: bool | None) -> None:
    """Install XDG autostart desktop entry (same file as config set ui.run_at_startup)."""
    result = install_autostart(minimized=minimized)
    if json_mode:
        emit(result, json_mode=True)
        return
    click.echo(str(result.get("message", "ok")))
    if result.get("exec"):
        click.echo(f"Exec: {result['exec']}")
    if not result.get("ok"):
        raise SystemExit(2)


@desktop_group.command("remove-autostart")
@click.option("--json", "json_mode", is_flag=True)
def desktop_remove_autostart(json_mode: bool) -> None:
    """Remove XDG autostart desktop entry and disable ui.run_at_startup."""
    result = remove_autostart()
    if json_mode:
        emit(result, json_mode=True)
        return
    click.echo(str(result.get("message", "ok")))
    if not result.get("ok"):
        raise SystemExit(2)
