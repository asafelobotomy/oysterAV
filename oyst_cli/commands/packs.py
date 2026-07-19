"""Pack-specific CLI command groups."""

from __future__ import annotations

from pathlib import Path

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.config import set_config_value
from oyst_core.packs.chkrootkit import ChkrootkitPack
from oyst_core.packs.clamav import ClamAVPack
from oyst_core.packs.clamonacc import ClamonaccPack
from oyst_core.packs.fail2ban import Fail2banPack
from oyst_core.packs.fangfrisch import FangfrischPack
from oyst_core.packs.firewall import FirewallPack
from oyst_core.packs.firewall_ops import FirewallOps
from oyst_core.packs.freshclam import FreshclamPack
from oyst_core.packs.lynis import LynisPack
from oyst_core.packs.maldet import MaldetPack
from oyst_core.packs.rkhunter import RKHunterPack
from oyst_core.packs.unhide import UnhidePack

UNHIDE_MODES = ("sys", "brute", "quick", "check", "fork", "proc", "reverse")


@click.group("clamav")
def clamav_group() -> None:
    """ClamAV operations."""


@clamav_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def clamav_status(json_mode: bool) -> None:
    """Installation and clamd status (upstream: clamscan --version, clamd probe)."""
    emit(ClamAVPack().doctor().model_dump(), json_mode=json_mode)


@clamav_group.command("scan")
@click.argument("path")
@click.option("--backend", default="auto")
@click.option("--json", "json_mode", is_flag=True)
def clamav_scan(path: str, backend: str, json_mode: bool) -> None:
    """Scan a path (upstream: clamscan/clamdscan -r)."""
    pack = ClamAVPack()
    res = pack.scan(path, backend=backend)
    findings = pack.parse_findings(res)
    payload = {
        "findings": [f.model_dump() for f in findings],
        "returncode": res.returncode,
    }
    emit(payload, json_mode=json_mode)
    if findings or res.returncode == 1:
        raise SystemExit(1)
    if res.returncode not in (0, 1):
        raise SystemExit(2)
    raise SystemExit(0)


@clamav_group.command("backend")
@click.argument("mode", type=click.Choice(["auto", "clamd", "clamscan"]))
@json_option
def clamav_backend(mode: str, json_mode: bool) -> None:
    """Set default scan backend (oyst-cli config: scan.backend)."""
    set_config_value("scan.backend", mode)
    payload = {"ok": True, "backend": mode}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(f"scan.backend={mode}")


@click.group("clamd")
def clamav_clamd_group() -> None:
    """ClamAV daemon (clamd) systemd control."""


@clamav_clamd_group.command("start")
@click.option("--json", "json_mode", is_flag=True)
def clamav_clamd_start(json_mode: bool) -> None:
    """Enable and start clamd (upstream: systemctl enable --now)."""
    ok, msg = ClamAVPack().clamd_start()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@clamav_clamd_group.command("stop")
@click.option("--json", "json_mode", is_flag=True)
def clamav_clamd_stop(json_mode: bool) -> None:
    """Stop clamd."""
    ok, msg = ClamAVPack().clamd_stop()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@clamav_clamd_group.command("restart")
@click.option("--json", "json_mode", is_flag=True)
def clamav_clamd_restart(json_mode: bool) -> None:
    """Restart clamd."""
    ok, msg = ClamAVPack().clamd_restart()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@clamav_clamd_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def clamav_clamd_status(json_mode: bool) -> None:
    """clamd unit and process status."""
    emit(ClamAVPack().clamd_status(), json_mode=json_mode)


@clamav_clamd_group.command("ensure")
@click.option("--json", "json_mode", is_flag=True)
def clamav_clamd_ensure(json_mode: bool) -> None:
    """Idempotent enable+start if clamd is not running."""
    ok, msg = ClamAVPack().clamd_ensure()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


clamav_group.add_command(clamav_clamd_group, name="clamd")


@click.group("freshclam")
def freshclam_group() -> None:
    """Signature updates."""


@freshclam_group.command("update")
@click.option("--json", "json_mode", is_flag=True)
def freshclam_update(json_mode: bool) -> None:
    """Update virus signatures (upstream: freshclam)."""
    ok, msg = FreshclamPack().update()
    payload = {"ok": ok, "message": msg}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@freshclam_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def freshclam_status(json_mode: bool) -> None:
    """Signature age and last update (upstream: freshclam log / db mtime)."""
    emit(FreshclamPack().status_text(), json_mode=json_mode)


@click.group("fangfrisch")
def fangfrisch_group() -> None:
    """Unofficial ClamAV signatures (complements freshclam)."""


@fangfrisch_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def fangfrisch_status(json_mode: bool) -> None:
    """Installation and config status."""
    emit(FangfrischPack().doctor().model_dump(), json_mode=json_mode)


@fangfrisch_group.command("ensure-config")
@click.option("--force", is_flag=True, help="Overwrite an existing fangfrisch.conf")
@click.option("--json", "json_mode", is_flag=True)
def fangfrisch_ensure_config(force: bool, json_mode: bool) -> None:
    """Write oysterAV-managed fangfrisch.conf for the active ClamAV DB dir."""
    ok, msg = FangfrischPack().ensure_config(force=force)
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@fangfrisch_group.command("initdb")
@click.option("--force", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def fangfrisch_initdb(force: bool, json_mode: bool) -> None:
    """Create fangfrisch SQLite schema (run once before refresh)."""
    ok, msg = FangfrischPack().initdb(force=force)
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@fangfrisch_group.command("refresh")
@click.option("--json", "json_mode", is_flag=True)
def fangfrisch_refresh(json_mode: bool) -> None:
    """Download/update unofficial signatures into the ClamAV DB directory."""
    ok, msg = FangfrischPack().refresh()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@click.group("clamonacc")
def clamonacc_group() -> None:
    """Real-time protection via clamonacc."""


@clamonacc_group.command("start")
@click.option("--json", "json_mode", is_flag=True)
def clamonacc_start(json_mode: bool) -> None:
    """Start on-access scanner (upstream: clamonacc)."""
    ok, msg = ClamonaccPack().start()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@clamonacc_group.command("stop")
@click.option("--json", "json_mode", is_flag=True)
def clamonacc_stop(json_mode: bool) -> None:
    """Stop on-access scanner."""
    ok, msg = ClamonaccPack().stop()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@clamonacc_group.command("enable")
@click.option("--json", "json_mode", is_flag=True)
def clamonacc_enable(json_mode: bool) -> None:
    """Ensure clamd, start clamonacc, and persist enabled config."""
    ok, msg = ClamonaccPack().enable()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@clamonacc_group.command("disable")
@click.option("--json", "json_mode", is_flag=True)
def clamonacc_disable(json_mode: bool) -> None:
    """Stop clamonacc and persist disabled config."""
    ok, msg = ClamonaccPack().disable()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@clamonacc_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def clamonacc_status(json_mode: bool) -> None:
    """Daemon and path configuration status."""
    emit(ClamonaccPack().doctor().model_dump(), json_mode=json_mode)


@clamonacc_group.group("paths")
def clamonacc_paths() -> None:
    """Manage monitored paths."""


@clamonacc_paths.command("list")
@click.option("--json", "json_mode", is_flag=True)
def paths_list(json_mode: bool) -> None:
    """List watched paths (config: clamonacc.paths)."""
    paths = ClamonaccPack().list_paths()
    if json_mode:
        emit(paths, json_mode=True)
    else:
        for p in paths:
            click.echo(p)


@clamonacc_paths.command("add")
@click.argument("path")
@json_option
def paths_add(path: str, json_mode: bool) -> None:
    """Add a watched path."""
    ClamonaccPack().add_path(path)
    payload = {"ok": True, "path": path, "action": "add"}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(f"Added {path}")


@clamonacc_paths.command("remove")
@click.argument("path")
@click.option("--confirm", is_flag=True)
@json_option
def paths_remove(path: str, confirm: bool, json_mode: bool) -> None:
    """Remove a watched path."""
    require_confirm(confirm, message="--confirm required to remove a clamonacc path")
    removed = ClamonaccPack().remove_path(path)
    payload = {"ok": removed, "path": path, "action": "remove", "removed": removed}
    if json_mode:
        emit(payload, json_mode=True)
    elif removed:
        click.echo(f"Removed {path}")
    else:
        click.echo(f"Path not in list: {path}", err=True)
    if not removed:
        raise SystemExit(2)


@click.group("rkhunter")
def rkhunter_group() -> None:
    """Rootkit Hunter."""


@rkhunter_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def rkhunter_status(json_mode: bool) -> None:
    """Installation and version status."""
    emit(RKHunterPack().doctor().model_dump(), json_mode=json_mode)


@rkhunter_group.command("scan")
@click.option("--skip-keypress/--no-skip-keypress", default=True)
@click.option("--json", "json_mode", is_flag=True)
def rkhunter_scan(skip_keypress: bool, json_mode: bool) -> None:
    """Run integrity check (upstream: rkhunter --check)."""
    pack = RKHunterPack()
    ok, output = pack.scan(skip_keypress=skip_keypress)
    findings = pack.parse_findings(output)
    emit({"findings": [f.model_dump() for f in findings], "ok": ok}, json_mode=json_mode)
    raise SystemExit(1 if findings else (0 if ok else 2))


@rkhunter_group.command("update")
@click.option("--json", "json_mode", is_flag=True)
def rkhunter_update(json_mode: bool) -> None:
    """Update data files (upstream: rkhunter --update)."""
    ok, msg = RKHunterPack().update()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@rkhunter_group.command("propupd")
@click.option("--confirm", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def rkhunter_propupd(confirm: bool, json_mode: bool) -> None:
    """Update property baseline (upstream: rkhunter --propupd)."""
    require_confirm(confirm, message="--confirm required to update rkhunter property baseline")
    ok, msg = RKHunterPack().propupd()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    if not ok:
        raise SystemExit(2)
    if not json_mode:
        click.echo("Baseline updated. Only run on trusted systems.")


@rkhunter_group.command("resolve")
@click.option("--threat", "threat_name", required=True, help="Finding threat_name")
@click.option("--path", "path", default="", help="Finding path (script/hidden)")
@click.option("--message", "message", default="", help="Finding message (SSH mapping)")
@click.option("--job-id", "job_id", default="", help="Patch this history job on success")
@click.option("--force", is_flag=True, help="Allow non-package-owned paths")
@click.option("--dry-run", is_flag=True)
@click.option("--confirm", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def rkhunter_resolve(
    threat_name: str,
    path: str,
    message: str,
    job_id: str,
    force: bool,
    dry_run: bool,
    confirm: bool,
    json_mode: bool,
) -> None:
    """Whitelist an rkhunter finding in /etc/rkhunter.d/oysterav-whitelist.conf."""
    from oyst_core.pack_jobs import run_rkhunter_resolve
    from oyst_core.packs.rkhunter_resolve import plan_resolve

    if not dry_run:
        require_confirm(
            confirm,
            message="--confirm required to write rkhunter whitelist overlay",
        )
    try:
        plan = plan_resolve(threat_name, path=path, message=message)
    except ValueError as exc:
        if json_mode:
            emit({"ok": False, "error": str(exc)}, json_mode=True)
        else:
            click.echo(str(exc), err=True)
        raise SystemExit(2) from None
    if not json_mode:
        click.echo(plan.explanation)
    result = run_rkhunter_resolve(
        threat_name,
        path=path,
        message=message,
        force=force,
        dry_run=dry_run,
        job_id=job_id or None,
    )
    if json_mode:
        emit(result, json_mode=True)
    elif not result.get("ok"):
        click.echo(str(result.get("error") or "resolve failed"), err=True)
    elif dry_run:
        click.echo(
            f"dry-run: would set {result.get('option')}={result.get('value')} "
            f"in {result.get('overlay')}"
        )
    else:
        click.echo(f"Updated {result.get('overlay')}: {result.get('option')}={result.get('value')}")
        click.echo("Re-run an integrity/custom scan to verify the warning is gone.")
    raise SystemExit(0 if result.get("ok") else 2)


@rkhunter_group.command("versioncheck")
@click.option("--json", "json_mode", is_flag=True)
def rkhunter_versioncheck(json_mode: bool) -> None:
    """Check for newer rkhunter release (upstream: rkhunter --versioncheck)."""
    ok, msg = RKHunterPack().versioncheck()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@click.group("chkrootkit")
def chkrootkit_group() -> None:
    """chkrootkit scanner."""


@chkrootkit_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def chkrootkit_status(json_mode: bool) -> None:
    """Installation and version status."""
    emit(ChkrootkitPack().doctor().model_dump(), json_mode=json_mode)


@chkrootkit_group.command("scan")
@click.option("--json", "json_mode", is_flag=True)
def chkrootkit_scan(json_mode: bool) -> None:
    """Run rootkit scan (upstream: chkrootkit)."""
    pack = ChkrootkitPack()
    ok, output = pack.scan()
    findings = pack.parse_findings(output)
    emit({"findings": [f.model_dump() for f in findings], "ok": ok}, json_mode=json_mode)
    raise SystemExit(1 if findings else (0 if ok else 2))


@click.group("lynis")
def lynis_group() -> None:
    """Lynis security audit."""


@lynis_group.command("audit")
@click.option("--profile", default=None, help="Profile name or path")
@click.option(
    "--scope",
    type=click.Choice(["host", "container-host"]),
    default="host",
    show_default=True,
)
@click.option("--quick/--full", default=True, show_default=True)
@click.option("--json", "json_mode", is_flag=True)
def lynis_audit(
    profile: str | None,
    scope: str,
    quick: bool,
    json_mode: bool,
) -> None:
    """Run system audit (upstream: lynis audit system)."""
    ok, output, score = LynisPack().audit(profile=profile, scope=scope, quick=quick)
    emit(
        {
            "ok": ok,
            "hardening_index": score,
            "scope": scope,
            "profile": profile,
            "output_tail": output[-4000:],
        },
        json_mode=json_mode,
    )
    raise SystemExit(0 if ok else 2)


@lynis_group.group("profiles")
def lynis_profiles_group() -> None:
    """Available Lynis audit profiles."""


@lynis_profiles_group.command("list")
@click.option("--json", "json_mode", is_flag=True)
def lynis_profiles_list(json_mode: bool) -> None:
    """List bundled and system profiles."""
    emit(LynisPack().list_profiles(), json_mode=json_mode)


@lynis_group.group("container")
def lynis_container_group() -> None:
    """Audit a running container from the Docker host."""


@lynis_container_group.command("audit")
@click.argument("container_id")
@click.option("--quick/--full", default=True, show_default=True)
@click.option("--json", "json_mode", is_flag=True)
def lynis_container_audit(container_id: str, quick: bool, json_mode: bool) -> None:
    """Run lynis inside a container (upstream: docker exec ... lynis audit system)."""
    ok, output, score = LynisPack().audit_container(container_id, quick=quick)
    emit(
        {
            "ok": ok,
            "hardening_index": score,
            "container_id": container_id,
            "output_tail": output[-4000:],
        },
        json_mode=json_mode,
    )
    raise SystemExit(0 if ok else 2)


@lynis_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def lynis_status(json_mode: bool) -> None:
    """Last audit score and timestamp."""
    emit(LynisPack().status(), json_mode=json_mode)


@lynis_group.command("export")
@click.argument("dest")
@json_option
def lynis_export(dest: str, json_mode: bool) -> None:
    """Export last report (upstream: lynis report)."""
    p = Path(dest).expanduser()
    if p.suffix == ".html":
        LynisPack().export_html(p)
    else:
        LynisPack().export_json(p)
    payload = {"ok": True, "path": str(p)}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(f"Exported to {p}")


@click.group("maldet")
def maldet_group() -> None:
    """Linux Malware Detect (optional)."""


@maldet_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def maldet_status(json_mode: bool) -> None:
    """Installation status."""
    emit(MaldetPack().doctor().model_dump(), json_mode=json_mode)


@maldet_group.command("scan")
@click.argument("path")
@click.option("--json", "json_mode", is_flag=True)
def maldet_scan(path: str, json_mode: bool) -> None:
    """Scan a path (upstream: maldet -a)."""
    pack = MaldetPack()
    ok, output = pack.scan(path)
    findings = pack.parse_findings(output)
    emit({"findings": [f.model_dump() for f in findings], "ok": ok}, json_mode=json_mode)
    raise SystemExit(1 if findings else (0 if ok else 2))


@maldet_group.command("update-sigs")
@click.option("--json", "json_mode", is_flag=True)
def maldet_update(json_mode: bool) -> None:
    """Update signatures (upstream: maldet -u)."""
    ok, msg = MaldetPack().update_sigs()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@maldet_group.command("list")
@click.option("--json", "json_mode", is_flag=True)
def maldet_list(json_mode: bool) -> None:
    """List scan reports (upstream: maldet -l)."""
    ok, output = MaldetPack().list_scans()
    if json_mode:
        emit({"ok": ok, "reports": output.splitlines()}, json_mode=True)
    else:
        click.echo(output)
    raise SystemExit(0 if ok else 2)


@maldet_group.command("quarantine")
@click.option("--json", "json_mode", is_flag=True)
def maldet_quarantine(json_mode: bool) -> None:
    """List maldet quarantine (upstream: maldet -q)."""
    ok, output = MaldetPack().quarantine_list()
    if json_mode:
        emit({"ok": ok, "entries": output.splitlines()}, json_mode=True)
    else:
        click.echo(output)
    raise SystemExit(0 if ok else 2)


@maldet_group.group("monitor")
def maldet_monitor_group() -> None:
    """Real-time inotify monitoring (upstream: maldet -m / systemd maldet.service)."""


@maldet_monitor_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def maldet_monitor_status(json_mode: bool) -> None:
    """Monitor daemon and prerequisite status."""
    emit(MaldetPack().monitor_status(), json_mode=json_mode)


@maldet_monitor_group.command("start")
@click.option("--json", "json_mode", is_flag=True)
def maldet_monitor_start(json_mode: bool) -> None:
    """Configure and start maldet monitor via systemd."""
    ok, msg = MaldetPack().monitor_start()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@maldet_monitor_group.command("stop")
@click.option("--json", "json_mode", is_flag=True)
def maldet_monitor_stop(json_mode: bool) -> None:
    """Stop maldet monitor."""
    ok, msg = MaldetPack().monitor_stop()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@maldet_monitor_group.group("paths")
def maldet_monitor_paths() -> None:
    """Monitor path list (config: maldet_monitor.paths)."""


@maldet_monitor_paths.command("list")
@click.option("--json", "json_mode", is_flag=True)
def maldet_paths_list(json_mode: bool) -> None:
    """List configured monitor paths."""
    paths = MaldetPack().list_monitor_paths()
    emit(paths, json_mode=json_mode)


@maldet_monitor_paths.command("add")
@click.argument("path")
@json_option
def maldet_paths_add(path: str, json_mode: bool) -> None:
    """Add a monitor path."""
    MaldetPack().add_monitor_path(path)
    payload = {"ok": True, "path": path, "action": "add"}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(f"Added {path}")


@maldet_monitor_paths.command("remove")
@click.argument("path")
@click.option("--confirm", is_flag=True)
@json_option
def maldet_paths_remove(path: str, confirm: bool, json_mode: bool) -> None:
    """Remove a monitor path."""
    require_confirm(confirm, message="--confirm required to remove a maldet monitor path")
    removed = MaldetPack().remove_monitor_path(path)
    payload = {"ok": removed, "path": path, "action": "remove", "removed": removed}
    if json_mode:
        emit(payload, json_mode=True)
    elif removed:
        click.echo(f"Removed {path}")
    else:
        click.echo(f"Path not in list: {path}", err=True)
    if not removed:
        raise SystemExit(2)


@maldet_monitor_group.command("events")
@click.option("--tail", default=20, show_default=True)
@click.option("--json", "json_mode", is_flag=True)
def maldet_monitor_events(tail: int, json_mode: bool) -> None:
    """Tail maldet event log."""
    ok, output = MaldetPack().tail_events(lines=tail)
    if json_mode:
        emit({"ok": ok, "lines": output.splitlines()}, json_mode=True)
    else:
        click.echo(output)
    raise SystemExit(0 if ok else 2)


@click.group("firewall")
def firewall_group() -> None:
    """Firewall detection, status, and rule management."""


@firewall_group.command("detect")
@click.option("--json", "json_mode", is_flag=True)
def firewall_detect(json_mode: bool) -> None:
    """Detect active firewall backend."""
    emit(FirewallPack().detect(), json_mode=json_mode)


@firewall_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def firewall_status(json_mode: bool) -> None:
    """Firewall backend status."""
    emit(FirewallPack().status(), json_mode=json_mode)


@firewall_group.command("audit")
@click.option("--json", "json_mode", is_flag=True)
def firewall_audit(json_mode: bool) -> None:
    """Read-only recommendations (includes fail2ban probe)."""
    pack = FirewallPack()
    recs = pack.audit()
    f2b = pack.fail2ban_status()
    payload = {"recommendations": recs, "fail2ban": f2b}
    if json_mode:
        emit(payload, json_mode=True)
        return
    for line in recs:
        click.echo(line)
    if f2b.get("installed"):
        click.echo("fail2ban: installed")
    else:
        click.echo("fail2ban: not installed (optional)")


@firewall_group.command("export")
@click.option("--json", "json_mode", is_flag=True)
def firewall_export(json_mode: bool) -> None:
    """Export current firewall rules snapshot."""
    emit(FirewallOps().export_rules(), json_mode=json_mode)


@firewall_group.command("rules")
@click.option("--verbose/--no-verbose", default=True, show_default=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_rules(verbose: bool, json_mode: bool) -> None:
    """Show detailed firewall rules (numbered UFW or all zones)."""
    ops = FirewallOps()
    text = ops.verbose_status() if verbose else str(ops.export_rules().get("rules", ""))
    if json_mode:
        emit({"rules": text}, json_mode=True)
    else:
        click.echo(text)


@firewall_group.command("plan")
@click.argument("proposed", type=click.Path(dir_okay=False))
@click.option("--json", "json_mode", is_flag=True)
def firewall_plan(proposed: str, json_mode: bool) -> None:
    """Diff proposed rule text against the active firewall snapshot."""
    path = Path(proposed).expanduser()
    if not path.is_file():
        raise click.ClickException(f"file not found: {path}")
    content = path.read_text(encoding="utf-8")
    emit(FirewallOps().plan_diff(content), json_mode=json_mode)


@firewall_group.group("ufw")
def firewall_ufw_group() -> None:
    """UFW rule management (when ufw is the active backend)."""


@firewall_ufw_group.command("allow")
@click.option("--port")
@click.option("--proto", default="tcp", show_default=True)
@click.option("--from", "from_addr", default=None)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_allow(
    port: str | None,
    proto: str,
    from_addr: str | None,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Add UFW allow rule."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate UFW rules")
    result = FirewallOps().ufw_rule(
        "allow", port=port, proto=proto, from_addr=from_addr, dry_run=dry_run
    )
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command("deny")
@click.option("--port")
@click.option("--proto", default="tcp", show_default=True)
@click.option("--from", "from_addr", default=None)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_deny(
    port: str | None,
    proto: str,
    from_addr: str | None,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Add UFW deny rule."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate UFW rules")
    result = FirewallOps().ufw_rule(
        "deny", port=port, proto=proto, from_addr=from_addr, dry_run=dry_run
    )
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command("limit")
@click.option("--port")
@click.option("--proto", default="tcp", show_default=True)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_limit(
    port: str | None,
    proto: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Add UFW rate-limit rule."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate UFW rules")
    result = FirewallOps().ufw_rule("limit", port=port, proto=proto, dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command("delete")
@click.option("--port")
@click.option("--proto", default="tcp", show_default=True)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_delete(
    port: str | None,
    proto: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Delete UFW rule."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate UFW rules")
    result = FirewallOps().ufw_rule("delete", port=port, proto=proto, dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command("default")
@click.argument("direction", type=click.Choice(["incoming", "outgoing", "routed"]))
@click.argument("policy", type=click.Choice(["allow", "deny", "reject"]))
@click.option("--confirm", is_flag=True)
@click.option("--force-lockout-risk", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_default(
    direction: str,
    policy: str,
    confirm: bool,
    force_lockout_risk: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Set UFW default policy."""
    require_confirm(
        confirm,
        dry_run=dry_run,
        message="--confirm required for default policy changes",
    )
    result = FirewallOps().ufw_default(
        direction,
        policy,
        dry_run=dry_run,
        force_lockout=force_lockout_risk,
    )
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command(
    "enable",
    epilog="""
Examples:
  oyst-cli firewall ufw enable --dry-run --json
  oyst-cli firewall ufw enable --confirm --json
""",
)
@click.option("--confirm", is_flag=True)
@click.option("--force-lockout-risk", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_enable(
    confirm: bool,
    force_lockout_risk: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Enable UFW."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to enable firewall")
    result = FirewallOps().ufw_lifecycle(
        "enable",
        dry_run=dry_run,
        force_lockout=force_lockout_risk,
    )
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command("disable")
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_disable(confirm: bool, dry_run: bool, json_mode: bool) -> None:
    """Disable UFW."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to disable firewall")
    result = FirewallOps().ufw_lifecycle("disable", dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_group.group("firewalld")
def firewall_firewalld_group() -> None:
    """firewalld rule management (when firewalld is active)."""


@firewall_firewalld_group.command("add-port")
@click.argument("port_spec")
@click.option("--zone", default="public", show_default=True)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewalld_add_port(
    port_spec: str,
    zone: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Add permanent port (e.g. 443/tcp)."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
    result = FirewallOps().firewalld_port("add-port", port_spec, zone=zone, dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_firewalld_group.command("remove-port")
@click.argument("port_spec")
@click.option("--zone", default="public", show_default=True)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewalld_remove_port(
    port_spec: str,
    zone: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Remove permanent port."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
    result = FirewallOps().firewalld_port("remove-port", port_spec, zone=zone, dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_firewalld_group.command("add-service")
@click.argument("service")
@click.option("--zone", default="public", show_default=True)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewalld_add_service(
    service: str,
    zone: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Add permanent service (e.g. ssh)."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
    result = FirewallOps().firewalld_service("add-service", service, zone=zone, dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_firewalld_group.command("remove-service")
@click.argument("service")
@click.option("--zone", default="public", show_default=True)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewalld_remove_service(
    service: str,
    zone: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Remove permanent service."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
    result = FirewallOps().firewalld_service("remove-service", service, zone=zone, dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_firewalld_group.command("rich-rule")
@click.argument("action", type=click.Choice(["add", "remove"]))
@click.argument("rule")
@click.option("--zone", default="public", show_default=True)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewalld_rich_rule(
    action: str,
    rule: str,
    zone: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Add or remove a rich rule."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
    fw_action = "add-rich-rule" if action == "add" else "remove-rich-rule"
    result = FirewallOps().firewalld_rich_rule(fw_action, rule, zone=zone, dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_firewalld_group.command("reload")
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewalld_reload(dry_run: bool, json_mode: bool) -> None:
    """Reload firewalld."""
    result = FirewallOps().firewalld_reload(dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


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


@click.group("unhide")
def unhide_group() -> None:
    """Hidden process detection (optional)."""


@unhide_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def unhide_status(json_mode: bool) -> None:
    """Installation status."""
    emit(UnhidePack().doctor().model_dump(), json_mode=json_mode)


@unhide_group.command("scan")
@click.option(
    "--mode",
    type=click.Choice(UNHIDE_MODES),
    default="sys",
    show_default=True,
    help="Scan technique (upstream: unhide <mode>)",
)
@click.option("--json", "json_mode", is_flag=True)
def unhide_scan(mode: str, json_mode: bool) -> None:
    """Run hidden-process detection."""
    pack = UnhidePack()
    ok, output = pack.scan(mode=mode)
    findings = pack.parse_findings(output)
    emit(
        {"findings": [f.model_dump() for f in findings], "ok": ok, "mode": mode},
        json_mode=json_mode,
    )
    raise SystemExit(1 if findings else (0 if ok else 2))
