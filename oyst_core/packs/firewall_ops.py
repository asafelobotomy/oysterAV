"""Firewall mutation operations with safety guards."""

from __future__ import annotations

import re
from dataclasses import dataclass

from oyst_core.audit import SecurityAudit
from oyst_core.packs.firewall import FirewallPack
from oyst_core.privileged.helper import run_privileged_helper
from oyst_core.privileged.runner import run_command, which
from oyst_core.privileged.validators import validate_port, validate_proto


@dataclass
class FirewallResult:
    ok: bool
    message: str
    argv: list[str] | None = None
    before: str | None = None
    after: str | None = None


class FirewallOps:
    def __init__(self) -> None:
        self._pack = FirewallPack()

    def _active_backend(self) -> str:
        det = self._pack.detect()
        if det.get("conflict"):
            raise ValueError("Multiple firewall managers active; resolve conflict first")
        active = str(det.get("active", "none"))
        if active == "none":
            raise ValueError("No active firewall backend detected")
        if active not in ("ufw", "firewalld"):
            raise ValueError(f"Unsupported firewall backend for mutations: {active}")
        return active

    def _snapshot(self, backend: str) -> str:
        if backend == "ufw":
            try:
                res = run_command(["ufw", "status", "verbose"], timeout=30)
                return res.stdout.strip()
            except (ValueError, OSError):
                return ""
        try:
            res = run_command(["firewall-cmd", "--list-all"], timeout=30)
            return res.stdout.strip()
        except (ValueError, OSError):
            return ""

    def _ssh_allowed(self, backend: str) -> bool:
        snap = self._snapshot(backend).lower()
        if backend == "ufw":
            return "22/tcp" in snap or "22 " in snap or "ssh" in snap
        return "ssh" in snap or "22/tcp" in snap or "22:tcp" in snap

    def _audit_mutate(
        self,
        action: str,
        *,
        ok: bool,
        argv: list[str],
        before: str,
        after: str,
    ) -> None:
        SecurityAudit().log(
            "firewall.mutate",
            action,
            success=ok,
            data={"argv": argv, "before": before[:2000], "after": after[:2000]},
        )

    def _run(
        self,
        action: str,
        argv: list[str],
        *,
        dry_run: bool = False,
        require_ssh: bool = False,
        force_lockout: bool = False,
    ) -> FirewallResult:
        backend = self._active_backend()
        if argv[0] != backend:
            raise ValueError(f"Backend mismatch: active={backend}, requested={argv[0]}")
        before = self._snapshot(backend)
        if require_ssh and not dry_run and not force_lockout and not self._ssh_allowed(backend):
            return FirewallResult(
                ok=False,
                message="SSH allow rule not detected; use --force-lockout-risk to proceed",
                argv=argv,
                before=before,
            )
        if dry_run:
            return FirewallResult(ok=True, message="dry-run", argv=argv, before=before)
        res = run_privileged_helper("firewall", argv)
        after = self._snapshot(backend)
        ok = res.returncode == 0
        self._audit_mutate(action, ok=ok, argv=argv, before=before, after=after)
        msg = (res.stdout or res.stderr or "").strip() or ("ok" if ok else "failed")
        return FirewallResult(ok=ok, message=msg, argv=argv, before=before, after=after)

    def export_rules(self) -> dict[str, object]:
        backend = self._pack.detect()
        active = str(backend.get("active", "none"))
        return {"backend": active, "rules": self._snapshot(active) if active != "none" else ""}

    def ufw_rule(
        self,
        action: str,
        *,
        port: str | None = None,
        proto: str = "tcp",
        from_addr: str | None = None,
        dry_run: bool = False,
    ) -> FirewallResult:
        self._active_backend()
        argv = ["ufw", action]
        if port:
            argv.extend(["--port", validate_port(port), "--proto", validate_proto(proto)])
        if from_addr:
            argv.extend(["--from", from_addr])
        return self._run(f"ufw.{action}", argv, dry_run=dry_run)

    def ufw_default(
        self,
        direction: str,
        policy: str,
        *,
        dry_run: bool = False,
        force_lockout: bool = False,
    ) -> FirewallResult:
        self._active_backend()
        argv = ["ufw", "default", direction, policy]
        require_ssh = direction == "incoming" and policy in ("deny", "reject")
        return self._run(
            "ufw.default",
            argv,
            dry_run=dry_run,
            require_ssh=require_ssh,
            force_lockout=force_lockout,
        )

    def ufw_lifecycle(
        self,
        action: str,
        *,
        dry_run: bool = False,
        force_lockout: bool = False,
    ) -> FirewallResult:
        self._active_backend()
        argv = ["ufw", action]
        require_ssh = action == "enable"
        return self._run(
            f"ufw.{action}",
            argv,
            dry_run=dry_run,
            require_ssh=require_ssh,
            force_lockout=force_lockout,
        )

    def firewalld_port(
        self,
        action: str,
        port_spec: str,
        *,
        zone: str = "public",
        dry_run: bool = False,
    ) -> FirewallResult:
        self._active_backend()
        argv = ["firewalld", action, port_spec, "--zone", zone]
        return self._run(f"firewalld.{action}", argv, dry_run=dry_run)

    def firewalld_service(
        self,
        action: str,
        service: str,
        *,
        zone: str = "public",
        dry_run: bool = False,
    ) -> FirewallResult:
        self._active_backend()
        argv = ["firewalld", action, service, "--zone", zone]
        return self._run(f"firewalld.{action}", argv, dry_run=dry_run)

    def firewalld_rich_rule(
        self,
        action: str,
        rule: str,
        *,
        zone: str = "public",
        dry_run: bool = False,
    ) -> FirewallResult:
        self._active_backend()
        argv = ["firewalld", action, rule, "--zone", zone]
        return self._run(f"firewalld.{action}", argv, dry_run=dry_run)

    def firewalld_reload(self, *, dry_run: bool = False) -> FirewallResult:
        self._active_backend()
        argv = ["firewalld", "reload"]
        return self._run("firewalld.reload", argv, dry_run=dry_run)

    def plan_diff(self, proposed: str) -> dict[str, object]:
        backend = self._active_backend()
        current = self._snapshot(backend)
        current_lines = set(current.splitlines())
        proposed_lines = set(proposed.splitlines())
        return {
            "backend": backend,
            "add": sorted(proposed_lines - current_lines),
            "remove": sorted(current_lines - proposed_lines),
        }

    def verbose_status(self) -> str:
        det = self._pack.detect()
        active = str(det.get("active", "none"))
        if active == "ufw" and which("ufw"):
            res = run_command(["ufw", "status", "numbered"], timeout=30)
            return res.stdout.strip()
        if active == "firewalld" and which("firewall-cmd"):
            res = run_command(["firewall-cmd", "--list-all-zones"], timeout=30)
            return res.stdout.strip()
        return self._snapshot(active)

    @staticmethod
    def parse_ssh_open(text: str) -> bool:
        lowered = text.lower()
        return bool(re.search(r"\b22\b|\bssh\b", lowered))
