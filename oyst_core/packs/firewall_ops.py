"""Firewall mutation operations with safety guards."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from oyst_core.audit import SecurityAudit
from oyst_core.packs.firewall import FirewallPack, invalidate_firewall_detect_cache
from oyst_core.privileged.helper import run_privileged_helper
from oyst_core.privileged.runner import run_command, which
from oyst_core.privileged.validators import (
    validate_cidr,
    validate_ip,
    validate_port,
    validate_port_spec,
    validate_proto,
    validate_rich_rule,
    validate_service_name,
    validate_zone,
)


@dataclass
class FirewallResult:
    ok: bool
    message: str
    argv: list[str] | None = None
    before: str | None = None
    after: str | None = None
    skipped: bool = False


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class FirewallOps:
    def __init__(self) -> None:
        self._pack = FirewallPack()

    def _active_backend(self) -> str:
        invalidate_firewall_detect_cache()
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

    def _ufw_rules_text(self) -> str:
        try:
            res = run_command(["ufw", "status", "verbose"], timeout=30)
            return res.stdout.strip()
        except (ValueError, OSError):
            return ""

    def _ssh_allowed(self, backend: str) -> bool:
        if backend == "ufw":
            return self.parse_ssh_open(self._ufw_rules_text())
        if which("firewall-cmd"):
            try:
                res = run_command(["firewall-cmd", "--query-service=ssh"], timeout=15)
                if res.returncode == 0:
                    return True
            except (ValueError, OSError):
                pass
        return self.parse_ssh_open(self._snapshot(backend))

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
            data={
                "argv": argv,
                "before_sha256": _sha(before),
                "after_sha256": _sha(after),
                "changed": before != after,
            },
        )

    def _run_helper(
        self,
        action: str,
        argv: list[str],
        *,
        before: str = "",
        dry_run: bool = False,
    ) -> FirewallResult:
        if dry_run:
            return FirewallResult(ok=True, message="dry-run", argv=argv, before=before)
        res = run_privileged_helper("firewall", argv)
        after = ""
        backend = argv[0] if argv else ""
        if backend in ("ufw", "firewalld"):
            after = self._snapshot(backend) if backend == "firewalld" else self._ufw_rules_text()
        ok = res.returncode == 0
        self._audit_mutate(action, ok=ok, argv=argv, before=before, after=after)
        invalidate_firewall_detect_cache()
        msg = (res.stdout or res.stderr or "").strip() or ("ok" if ok else "failed")
        return FirewallResult(ok=ok, message=msg, argv=argv, before=before, after=after)

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
        return self._run_helper(action, argv, before=before, dry_run=dry_run)

    def ensure_firewall_enabled(
        self,
        *,
        force_lockout: bool = False,
        dry_run: bool = False,
    ) -> FirewallResult:
        """Enable UFW or firewalld when installed but inactive (SSH-safe)."""
        from oyst_core.packs.firewall_ensure import ensure_firewall_enabled as _ensure

        return _ensure(force_lockout=force_lockout, dry_run=dry_run)

    def set_managed_enabled(
        self,
        enabled: bool,
        *,
        force_lockout: bool = False,
        dry_run: bool = False,
    ) -> FirewallResult:
        """Enable or stop oysterAV-managed firewall (UFW / firewalld only)."""
        from oyst_core.packs.firewall_ensure import set_managed_enabled as _set

        return _set(enabled, force_lockout=force_lockout, dry_run=dry_run)

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
        force_lockout: bool = False,
    ) -> FirewallResult:
        self._active_backend()
        port_val = validate_port(port) if port else None
        if action in {"delete", "deny"} and port_val == "22" and not force_lockout and not dry_run:
            return FirewallResult(
                ok=False,
                message="refusing to delete/deny SSH port 22; use --force-lockout-risk",
            )
        argv = ["ufw", action]
        if port_val:
            argv.extend(["--port", port_val, "--proto", validate_proto(proto)])
        if from_addr:
            src = from_addr.strip()
            validated = validate_cidr(src) if "/" in src else validate_ip(src)
            argv.extend(["--from", validated])
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
        if action == "enable":
            det = self._pack.detect()
            if not det.get("conflict") and str(det.get("active", "none")) == "none":
                return self.ensure_firewall_enabled(
                    force_lockout=force_lockout,
                    dry_run=dry_run,
                )
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
        argv = [
            "firewalld",
            action,
            validate_port_spec(port_spec),
            "--zone",
            validate_zone(zone),
        ]
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
        argv = [
            "firewalld",
            action,
            validate_service_name(service),
            "--zone",
            validate_zone(zone),
        ]
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
        argv = [
            "firewalld",
            action,
            validate_rich_rule(rule),
            "--zone",
            validate_zone(zone),
        ]
        return self._run(f"firewalld.{action}", argv, dry_run=dry_run)

    def firewalld_lifecycle(self, action: str, *, dry_run: bool = False) -> FirewallResult:
        if action != "disable":
            raise ValueError(f"unsupported firewalld lifecycle action: {action}")
        self._active_backend()
        return self._run("firewalld.disable", ["firewalld", "disable"], dry_run=dry_run)

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
        """True only when an allow/limit/accept line mentions SSH or port 22."""
        for line in text.lower().splitlines():
            if not (re.search(r"\b22\b", line) or re.search(r"\bssh\b", line)):
                continue
            if re.search(r"\b(deny|reject|drop)\b", line):
                continue
            if re.search(r"\b(allow|limit|accept)\b", line):
                return True
        return False
