"""Root-owned privileged helper invoked via polkit (oyst-helper)."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from oyst_core.privileged.validators import (
    FIREWALLD_PORT_ACTIONS,
    FIREWALLD_RICH_ACTIONS,
    FIREWALLD_SERVICE_ACTIONS,
    UFW_DEFAULT_DIRS,
    UFW_DEFAULT_POLICIES,
    UFW_LIFECYCLE,
    UFW_RULE_ACTIONS,
    validate_cidr,
    validate_ip,
    validate_jail,
    validate_monitor_mode,
    validate_port,
    validate_port_spec,
    validate_proto,
    validate_rich_rule,
    validate_service_name,
    validate_systemctl_action,
    validate_unit,
    validate_zone,
)

ALLOWED_PACKAGE_MANAGERS = frozenset({"pacman", "dnf", "apt-get", "apt"})
ALLOWED_SCANNER_BINARIES = frozenset(
    {
        "rkhunter",
        "chkrootkit",
        "lynis",
        "unhide",
        "unhide-linux",
        "clamonacc",
    }
)
PACKAGE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.+_-]{0,127}$")
USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
RKHUNTER_FLAGS = frozenset({"--update", "--propupd", "--versioncheck", "--check", "--sk", "--rwo"})
UNHIDE_MODES = frozenset({"sys", "brute", "quick", "check", "fork", "proc", "reverse"})
CLAMONACC_FLAGS = frozenset({"--foreground", "-F", "--fdpass"})


def _validate_package_name(name: str) -> str:
    cleaned = name.strip()
    if not PACKAGE_NAME_RE.match(cleaned):
        raise ValueError(f"invalid package name: {name}")
    return cleaned


def _validate_username(name: str) -> str:
    cleaned = name.strip()
    if not USERNAME_RE.match(cleaned):
        raise ValueError(f"invalid username: {name}")
    return cleaned


def _validate_package_manager_argv(base: str, argv: Sequence[str]) -> list[str]:
    """Allow only install/sync shapes with validated package names."""
    args = list(argv[1:])
    if base == "pacman":
        if not args or args[0] not in ("-S", "-Sy"):
            raise ValueError("pacman only allows -S/-Sy install")
        sync_flag = args[0]
        rest = args[1:]
        if "--noconfirm" not in rest:
            raise ValueError("pacman install requires --noconfirm")
        packages = [a for a in rest if a != "--noconfirm"]
        if not packages:
            raise ValueError("pacman install requires package names")
        return [base, sync_flag, "--noconfirm", *(_validate_package_name(p) for p in packages)]
    if base == "dnf":
        if len(args) < 2 or args[0] != "install" or args[1] != "-y":
            raise ValueError("dnf only allows: install -y <packages>")
        packages = args[2:]
        if not packages:
            raise ValueError("dnf install requires package names")
        return [base, "install", "-y", *(_validate_package_name(p) for p in packages)]
    if base in ("apt-get", "apt"):
        if len(args) < 2 or args[0] != "install" or args[1] != "-y":
            raise ValueError(f"{base} only allows: install -y <packages>")
        packages = args[2:]
        if not packages:
            raise ValueError(f"{base} install requires package names")
        return [base, "install", "-y", *(_validate_package_name(p) for p in packages)]
    raise ValueError(f"unsupported package manager: {base}")


def _validate_scanner_argv(base: str, argv: Sequence[str]) -> list[str]:
    """Allow constrained privileged scanner invocations (basename + known flags)."""
    # Preserve caller path (runtime private binaries) but validate by basename.
    binary = argv[0]
    args = list(argv[1:])
    if base == "rkhunter":
        if not args:
            raise ValueError("rkhunter requires an action flag")
        for flag in args:
            if flag not in RKHUNTER_FLAGS:
                raise ValueError(f"rkhunter flag not allowlisted: {flag}")
        if args[0] not in ("--update", "--propupd", "--versioncheck", "--check"):
            raise ValueError("rkhunter action not allowlisted")
        return [binary, *args]
    if base == "chkrootkit":
        if args:
            raise ValueError("chkrootkit takes no arguments")
        return [binary]
    if base == "lynis":
        if len(args) < 2 or args[0] != "audit" or args[1] != "system":
            raise ValueError("lynis only allows: audit system ...")
        allowed_opts = {"--no-colors", "--quick", "--profile"}
        i = 2
        out = [binary, "audit", "system"]
        while i < len(args):
            opt = args[i]
            if opt not in allowed_opts:
                raise ValueError(f"lynis option not allowlisted: {opt}")
            out.append(opt)
            if opt == "--profile":
                i += 1
                if i >= len(args):
                    raise ValueError("lynis --profile requires a path")
                profile = Path(args[i])
                if not profile.is_absolute() or ".." in profile.parts:
                    raise ValueError("lynis profile must be an absolute path")
                out.append(str(profile))
            i += 1
        return out
    if base in ("unhide", "unhide-linux"):
        if len(args) != 1 or args[0] not in UNHIDE_MODES:
            raise ValueError("unhide requires a single allowlisted mode")
        return [binary, args[0]]
    if base == "clamonacc":
        return _validate_clamonacc_argv(binary, args)
    raise ValueError(f"scanner not allowlisted: {base}")


def _validate_clamonacc_argv(binary: str, args: Sequence[str]) -> list[str]:
    """Allow --foreground (required), optional --fdpass and --include-list=ABS_PATH."""
    if "--foreground" not in args and "-F" not in args:
        raise ValueError("clamonacc requires --foreground")
    out: list[str] = [binary]
    for arg in args:
        if arg in ("--foreground", "-F", "--fdpass"):
            out.append("--foreground" if arg == "-F" else arg)
            continue
        if arg.startswith("--include-list="):
            path = Path(arg.split("=", 1)[1])
            if not path.is_absolute() or ".." in path.parts:
                raise ValueError("clamonacc --include-list must be an absolute path")
            if any(ch in str(path) for ch in (";", "|", "&", "$", "`", "\n", "\r")):
                raise ValueError("clamonacc --include-list path contains disallowed characters")
            if not path.is_file():
                raise ValueError(f"clamonacc include list not found: {path}")
            out.append(f"--include-list={path}")
            continue
        raise ValueError(f"clamonacc flag not allowlisted: {arg}")
    return out


def _validate_run_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError("empty command")
    base = os.path.basename(argv[0])
    if base in ALLOWED_PACKAGE_MANAGERS:
        return _validate_package_manager_argv(base, argv)
    if base in ALLOWED_SCANNER_BINARIES:
        return _validate_scanner_argv(base, argv)
    if base == "loginctl":
        if len(argv) != 3 or argv[1] not in ("enable-linger", "disable-linger"):
            raise ValueError(f"loginctl action not allowed: {' '.join(argv[1:])}")
        return ["loginctl", argv[1], _validate_username(argv[2])]
    raise ValueError(f"command not allowlisted: {base}")


def _validate_install_script(path: str) -> Path:
    script = Path(path).resolve()
    if script.name != "install.sh":
        raise ValueError("only install.sh scripts are allowed")
    if not script.is_file():
        raise ValueError(f"install script not found: {script}")
    parent_name = script.parent.name
    if not parent_name.startswith("maldetect-"):
        raise ValueError("install.sh must live in a maldetect-* directory")
    if not any(p.startswith("oyst-maldet-") for p in script.parts):
        raise ValueError("install.sh must be under an oyst-maldet-* temp extract")
    under_tmp = False
    for root in (Path("/tmp").resolve(), Path("/var/tmp").resolve()):
        try:
            script.relative_to(root)
            under_tmp = True
            break
        except ValueError:
            continue
    if not under_tmp:
        raise ValueError("install.sh must be under /tmp or /var/tmp")
    return script


def _parse_flag(argv: Sequence[str], flag: str) -> tuple[str | None, list[str]]:
    rest = list(argv)
    value: str | None = None
    if flag in rest:
        idx = rest.index(flag)
        if idx + 1 >= len(rest):
            raise ValueError(f"missing value for {flag}")
        value = rest[idx + 1]
        del rest[idx : idx + 2]
    return value, rest


def _has_flag(argv: Sequence[str], flag: str) -> bool:
    return flag in argv


def _build_ufw_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError("ufw subcommand required")
    action = argv[0]
    rest = list(argv[1:])
    if action in UFW_RULE_ACTIONS:
        port, rest = _parse_flag(rest, "--port")
        proto, rest = _parse_flag(rest, "--proto")
        from_addr, rest = _parse_flag(rest, "--from")
        to_port, rest = _parse_flag(rest, "--to-port")
        if rest:
            raise ValueError(f"unexpected ufw args: {' '.join(rest)}")
        cmd = ["ufw", action]
        if from_addr:
            src = validate_cidr(from_addr) if "/" in from_addr else validate_ip(from_addr)
            cmd.extend(["from", src])
        if port:
            cmd.extend(["to", "any", "port", validate_port(port)])
        elif to_port:
            cmd.extend(["to", "any", "port", validate_port(to_port)])
        if proto:
            cmd.append(validate_proto(proto))
        return cmd
    if action == "default":
        if len(rest) < 2:
            raise ValueError("usage: ufw default <incoming|outgoing|routed> <allow|deny|reject>")
        direction = rest[0]
        policy = rest[1]
        if direction not in UFW_DEFAULT_DIRS:
            raise ValueError(f"invalid default direction: {direction}")
        if policy not in UFW_DEFAULT_POLICIES:
            raise ValueError(f"invalid default policy: {policy}")
        return ["ufw", "default", direction, policy]
    if action in UFW_LIFECYCLE:
        if rest:
            raise ValueError(f"unexpected ufw args: {' '.join(rest)}")
        if action == "reload":
            return ["ufw", "reload"]
        return ["ufw", action]
    raise ValueError(f"unknown ufw action: {action}")


def _build_firewalld_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError("firewalld subcommand required")
    action = argv[0]
    rest = list(argv[1:])
    zone, rest = _parse_flag(rest, "--zone")
    zone_name = validate_zone(zone or "public")
    if action in FIREWALLD_PORT_ACTIONS:
        if not rest:
            raise ValueError("port spec required")
        port_spec = validate_port_spec(rest[0])
        fw_action = "add-port" if action == "add-port" else "remove-port"
        return [
            "firewall-cmd",
            f"--{fw_action}={port_spec}",
            f"--zone={zone_name}",
            "--permanent",
        ]
    if action in FIREWALLD_SERVICE_ACTIONS:
        if not rest:
            raise ValueError("service name required")
        service = validate_service_name(rest[0])
        fw_action = "add-service" if action == "add-service" else "remove-service"
        return [
            "firewall-cmd",
            f"--{fw_action}={service}",
            f"--zone={zone_name}",
            "--permanent",
        ]
    if action in FIREWALLD_RICH_ACTIONS:
        if not rest:
            raise ValueError("rich rule required")
        rule = validate_rich_rule(" ".join(rest))
        fw_action = "add-rich-rule" if action == "add-rich-rule" else "remove-rich-rule"
        return [
            "firewall-cmd",
            f"--{fw_action}={rule}",
            f"--zone={zone_name}",
            "--permanent",
        ]
    if action == "reload":
        return ["firewall-cmd", "--reload"]
    raise ValueError(f"unknown firewalld action: {action}")


def _build_firewall_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError("firewall backend required")
    backend = argv[0]
    if backend == "ufw":
        return _build_ufw_argv(argv[1:])
    if backend == "firewalld":
        built = _build_firewalld_argv(argv[1:])
        if built[-1] == "--permanent":
            return built
        return built
    raise ValueError(f"unknown firewall backend: {backend}")


def _run_fail2ban_client(argv: list[str]) -> None:
    """Run fail2ban-client as root; raise ValueError on failure."""
    proc = subprocess.run(argv, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "fail2ban-client failed").strip()
        raise ValueError(detail)


def _persist_fail2ban_ignoreip(jail: str, ip: str) -> None:
    dropin_dir = Path("/etc/fail2ban/jail.d")
    dropin_dir.mkdir(parents=True, exist_ok=True)
    dropin = dropin_dir / f"oysterav-{jail}-ignore.conf"
    dropin.write_text(f"[{jail}]\nignoreip = {ip}\n", encoding="utf-8")
    _run_fail2ban_client(["fail2ban-client", "reload"])


def _build_fail2ban_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError("fail2ban action required")
    action = argv[0]
    rest = list(argv[1:])
    if action == "banned":
        return ["fail2ban-client", "banned"]
    if action == "unban":
        if not rest:
            raise ValueError("IP required")
        return ["fail2ban-client", "unban", validate_ip(rest[0])]
    if action == "unbanip":
        if len(rest) < 2:
            raise ValueError("usage: unbanip <jail> <ip>")
        return [
            "fail2ban-client",
            "set",
            validate_jail(rest[0]),
            "unbanip",
            validate_ip(rest[1]),
        ]
    if action == "addignoreip":
        if len(rest) < 2:
            raise ValueError("usage: addignoreip <jail> <ip>")
        return [
            "fail2ban-client",
            "set",
            validate_jail(rest[0]),
            "addignoreip",
            validate_ip(rest[1]),
        ]
    if action == "jail-start":
        if not rest:
            raise ValueError("jail name required")
        return ["fail2ban-client", "start", validate_jail(rest[0])]
    if action == "jail-stop":
        if not rest:
            raise ValueError("jail name required")
        return ["fail2ban-client", "stop", validate_jail(rest[0])]
    if action == "reload":
        cmd = ["fail2ban-client", "reload"]
        if _has_flag(rest, "--unban"):
            cmd.append("--unban")
        return cmd
    if action == "persist-ignoreip":
        if len(rest) < 2:
            raise ValueError("usage: persist-ignoreip <jail> <ip>")
        jail = validate_jail(rest[0])
        ip = validate_ip(rest[1])
        _persist_fail2ban_ignoreip(jail, ip)
        return ["true"]
    if action == "unban-flow":
        # One polkit auth: unban, optional ignore, optional persist+reload.
        # usage: unban-flow <ip> [--jail NAME] [--ignore] [--persist]
        if not rest:
            raise ValueError("IP required")
        ip = validate_ip(rest[0])
        rem = list(rest[1:])
        jail_opt, rem = _parse_flag(rem, "--jail")
        ignore = _has_flag(rem, "--ignore")
        persist = _has_flag(rem, "--persist")
        rem = [a for a in rem if a not in ("--ignore", "--persist")]
        if rem:
            raise ValueError(f"unexpected unban-flow args: {' '.join(rem)}")
        if (ignore or persist) and not jail_opt:
            raise ValueError("--ignore/--persist require --jail")
        if jail_opt:
            jail_name = validate_jail(jail_opt)
            _run_fail2ban_client(["fail2ban-client", "set", jail_name, "unbanip", ip])
            if ignore:
                _run_fail2ban_client(["fail2ban-client", "set", jail_name, "addignoreip", ip])
            if persist:
                _persist_fail2ban_ignoreip(jail_name, ip)
        else:
            _run_fail2ban_client(["fail2ban-client", "unban", ip])
        return ["true"]
    raise ValueError(f"unknown fail2ban action: {action}")


def _build_systemctl_argv(argv: Sequence[str]) -> list[str]:
    if len(argv) < 2:
        raise ValueError("usage: systemctl <action> <unit>")
    action = validate_systemctl_action(argv[0])
    unit = validate_unit(argv[1])
    if action == "enable-now":
        return ["systemctl", "enable", "--now", unit]
    if action == "disable-now":
        return ["systemctl", "disable", "--now", unit]
    return ["systemctl", action, unit]


def _apply_maldet_monitor_mode(mode: str) -> None:
    conf_path = Path("/usr/local/maldetect/conf.maldet")
    if not conf_path.is_file():
        raise ValueError(f"maldet config not found: {conf_path}")
    text = conf_path.read_text(encoding="utf-8")
    key = "default_monitor_mode"
    new_line = f'{key}="{mode}"'
    updated: list[str] = []
    found = False
    for line in text.splitlines():
        if line.strip().startswith(f"{key}="):
            updated.append(new_line)
            found = True
        else:
            updated.append(line)
    if not found:
        updated.append(new_line)
    conf_path.write_text("\n".join(updated) + "\n", encoding="utf-8")


def _build_maldet_config_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError(
            "usage: maldet-config set-monitor-mode <users|paths> | start-monitor <users|paths>"
        )
    if argv[0] == "set-monitor-mode":
        if len(argv) < 2:
            raise ValueError("usage: maldet-config set-monitor-mode <users|paths>")
        mode = validate_monitor_mode(argv[1])
        _apply_maldet_monitor_mode(mode)
        return ["true"]
    if argv[0] == "start-monitor":
        # One polkit auth: write monitor mode + enable/start maldet unit.
        if len(argv) < 2:
            raise ValueError("usage: maldet-config start-monitor <users|paths>")
        mode = validate_monitor_mode(argv[1])
        _apply_maldet_monitor_mode(mode)
        unit = validate_unit("maldet")
        proc = subprocess.run(
            ["systemctl", "enable", "--now", unit],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "systemctl enable --now failed").strip()
            raise ValueError(detail)
        return ["true"]
    raise ValueError(
        "usage: maldet-config set-monitor-mode <users|paths> | start-monitor <users|paths>"
    )


def _build_rkhunter_whitelist_argv(argv: Sequence[str]) -> list[str]:
    """Write allowlisted directive(s) into /etc/rkhunter.d overlays."""
    from oyst_core.packs.rkhunter_resolve import (
        apply_disable_tests_overlay,
        apply_overlay_line,
        apply_overlay_lines,
    )

    if not argv:
        raise ValueError(
            "usage: rkhunter-whitelist set <OPTION> <value> | set-many OPTION=value ... "
            "| set-disable-tests [test ...]"
        )
    if argv[0] == "set":
        if len(argv) < 3:
            raise ValueError("usage: rkhunter-whitelist set <OPTION> <value>")
        apply_overlay_line(argv[1], argv[2])
        return ["true"]
    if argv[0] == "set-many":
        if len(argv) < 2:
            raise ValueError("usage: rkhunter-whitelist set-many OPTION=value ...")
        directives: list[tuple[str, str]] = []
        for item in argv[1:]:
            if "=" not in item:
                raise ValueError(f"expected OPTION=value, got: {item}")
            option, _, value = item.partition("=")
            directives.append((option, value))
        apply_overlay_lines(directives)
        return ["true"]
    if argv[0] == "set-disable-tests":
        apply_disable_tests_overlay(list(argv[1:]))
        return ["true"]
    raise ValueError(
        "usage: rkhunter-whitelist set <OPTION> <value> | set-many OPTION=value ... "
        "| set-disable-tests [test ...]"
    )


def _run_validated(cmd: list[str]) -> int:
    if cmd == ["true"]:
        return 0
    proc = subprocess.run(cmd, check=False)
    if cmd[0] == "firewall-cmd" and "--permanent" in cmd and proc.returncode == 0:
        reload_proc = subprocess.run(["firewall-cmd", "--reload"], check=False)
        return reload_proc.returncode
    return proc.returncode


def run_helper_argv(argv: Sequence[str]) -> int:
    if not argv:
        print(
            "usage: oyst-helper run|install-script|firewall|fail2ban|systemctl|"
            "maldet-config|rkhunter-whitelist",
            file=sys.stderr,
        )
        return 2
    subcommand = argv[0]
    if subcommand == "run":
        try:
            cmd = _validate_run_argv(argv[1:])
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        proc = subprocess.run(cmd, check=False)
        return proc.returncode
    if subcommand == "install-script":
        if len(argv) < 2:
            print("usage: oyst-helper install-script /path/to/install.sh", file=sys.stderr)
            return 2
        try:
            script = _validate_install_script(argv[1])
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        proc = subprocess.run(
            ["bash", str(script)],
            cwd=str(script.parent),
            check=False,
        )
        return proc.returncode
    builders = {
        "firewall": _build_firewall_argv,
        "fail2ban": _build_fail2ban_argv,
        "systemctl": _build_systemctl_argv,
        "maldet-config": _build_maldet_config_argv,
        "rkhunter-whitelist": _build_rkhunter_whitelist_argv,
    }
    if subcommand in builders:
        try:
            cmd = builders[subcommand](argv[1:])
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        return _run_validated(cmd)
    print(f"unknown subcommand: {subcommand}", file=sys.stderr)
    return 2


def main() -> None:
    raise SystemExit(run_helper_argv(sys.argv[1:]))


if __name__ == "__main__":
    main()
