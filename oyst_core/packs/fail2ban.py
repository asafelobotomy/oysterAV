"""fail2ban intrusion-prevention pack (optional, host-integrated)."""

from __future__ import annotations

import re

from oyst_core.audit import SecurityAudit
from oyst_core.models import PackStatus, PackTier
from oyst_core.packs.base import Pack
from oyst_core.privileged.helper import run_privileged_helper
from oyst_core.privileged.runner import run_command, which
from oyst_core.privileged.validators import validate_ip, validate_jail


class Fail2banPack(Pack):
    name = "fail2ban"
    tier = PackTier.OPTIONAL
    system_bins = ["fail2ban-client"]

    def doctor(self) -> PackStatus:
        binary = which("fail2ban-client")
        installed = binary is not None
        version = None
        if binary:
            try:
                res = run_command(["fail2ban-client", "-V"], timeout=15)
                match = re.search(r"([\d.]+)", (res.stdout or res.stderr or "").strip())
                if match:
                    version = match.group(1)
            except (ValueError, OSError):
                version = None
        status = self._base_status(installed, version)
        if installed:
            svc = self.service_status()
            status.details = svc
            status.details["binary"] = binary
            from oyst_core.packs.firewall import FirewallPack

            fw = FirewallPack().detect()
            status.details["firewall"] = fw.get("active", "none")
            if not svc.get("running"):
                status.message = "fail2ban installed but service may not be running"
            elif fw.get("active") == "none":
                status.message = (
                    "fail2ban works best with an active firewall backend (ufw or firewalld)"
                )
        return status

    def service_status(self) -> dict[str, object]:
        if not which("fail2ban-client"):
            return {"installed": False, "running": False, "jails": []}
        try:
            res = run_command(["fail2ban-client", "status"], timeout=30)
            output = res.stdout.strip()
            running = res.returncode == 0
            jails = self._parse_jail_list(output)
            return {
                "installed": True,
                "running": running,
                "jails": jails,
                "output": output,
            }
        except (ValueError, OSError) as exc:
            return {"installed": True, "running": False, "error": str(exc), "jails": []}

    def _parse_jail_list(self, output: str) -> list[str]:
        for line in output.splitlines():
            if "Jail list:" in line or "Jail list" in line:
                _, _, tail = line.partition(":")
                return [j.strip() for j in tail.split(",") if j.strip()]
        return []

    def jail_status(self, jail: str) -> dict[str, object]:
        if not which("fail2ban-client"):
            return {"installed": False, "error": "fail2ban-client not installed"}
        try:
            res = run_command(["fail2ban-client", "status", jail], timeout=30)
            banned = 0
            for line in res.stdout.splitlines():
                match = re.search(r"Currently banned:\s*(\d+)", line)
                if match:
                    banned = int(match.group(1))
            return {
                "jail": jail,
                "ok": res.returncode == 0,
                "banned_count": banned,
                "output": res.stdout.strip(),
            }
        except (ValueError, OSError) as exc:
            return {"jail": jail, "ok": False, "error": str(exc)}

    def banned(self) -> dict[str, object]:
        if not which("fail2ban-client"):
            return {"installed": False, "jails": {}}
        res = run_privileged_helper("fail2ban", ["banned"])
        if res.returncode != 0:
            return {"installed": True, "ok": False, "error": res.stderr or res.stdout, "jails": {}}
        jails: dict[str, list[str]] = {}
        current: str | None = None
        for line in (res.stdout or "").splitlines():
            stripped = line.strip()
            if stripped.endswith(":") and not stripped.startswith("-"):
                current = stripped.rstrip(":")
                jails[current] = []
            elif current and stripped:
                jails[current].append(stripped)
        return {"installed": True, "ok": True, "jails": jails}

    def unban(
        self,
        ip: str,
        *,
        jail: str | None = None,
        ignore: bool = False,
        persist: bool = False,
    ) -> tuple[bool, str]:
        addr = validate_ip(ip)
        if jail:
            validate_jail(jail)
        # Single helper invocation (unban + optional ignore/persist) → one polkit auth.
        argv: list[str] = ["unban-flow", addr]
        if jail:
            argv.extend(["--jail", jail])
            if ignore:
                argv.append("--ignore")
            if persist:
                argv.append("--persist")
        res = run_privileged_helper("fail2ban", argv)
        ok = res.returncode == 0
        SecurityAudit().log(
            "fail2ban.unban",
            addr,
            success=ok,
            data={"jail": jail, "ignore": ignore, "persist": persist},
        )
        msg = (res.stdout or res.stderr or "").strip() or ("ok" if ok else "failed")
        return ok, msg

    def _persist_ignoreip(self, jail: str, ip: str) -> tuple[bool, str]:
        res = run_privileged_helper("fail2ban", ["persist-ignoreip", jail, ip])
        ok = res.returncode == 0
        return ok, res.stderr or ("ok" if ok else "persist failed")

    def set_jail_enabled(self, jail: str, *, enabled: bool) -> tuple[bool, str]:
        validate_jail(jail)
        action = "jail-start" if enabled else "jail-stop"
        res = run_privileged_helper("fail2ban", [action, jail])
        ok = res.returncode == 0
        SecurityAudit().log(
            "fail2ban.jail",
            f"{'enable' if enabled else 'disable'}:{jail}",
            success=ok,
        )
        msg = (res.stdout or res.stderr or "").strip() or ("ok" if ok else "failed")
        return ok, msg

    def reload(self, *, unban: bool = False) -> tuple[bool, str]:
        argv = ["reload"]
        if unban:
            argv.append("--unban")
        res = run_privileged_helper("fail2ban", argv)
        ok = res.returncode == 0
        msg = (res.stdout or res.stderr or "").strip() or ("ok" if ok else "failed")
        return ok, msg
