"""JobOrchestrator helpers: progress, audit, quarantine, cancel, status."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from oyst_core.config import load_config
from oyst_core.finding_status import MALWARE_PACKS
from oyst_core.models import Finding, FindingSeverity, ScanResult
from oyst_core.packs.clamd_onaccess import probe_onaccess_prevention
from oyst_core.quarantine import QuarantineVault

if TYPE_CHECKING:
    from oyst_core.events import EventLog
    from oyst_core.registry import PackRegistry


class OrchestratorHelpersMixin:
    """Mixin methods mixed into JobOrchestrator."""

    events: EventLog
    registry: PackRegistry

    def _emit_progress(
        self,
        job_id: str,
        *,
        pack: str,
        message: str,
        percent: float,
        state: str,
        on_progress: Callable[[str, float], None] | None,
    ) -> None:
        self.events.set_job_progress(
            job_id,
            pack=pack,
            message=message,
            percent=percent,
            state=state,
        )
        if on_progress is not None:
            on_progress(pack or message, percent)

    def _run_audit_pack(self, pack: object) -> list[Finding]:
        """Run audit-only packs (e.g. lynis) and map results to findings."""
        audit = getattr(pack, "audit", None)
        if not callable(audit):
            return []
        quick = load_config().lynis.quick
        ok, output, score = audit(quick=quick)
        pack_name = str(getattr(pack, "name", "audit"))
        if not ok and "not installed" in str(output):
            return []
        message = "Hardening audit completed"
        if score is not None:
            message = f"Hardening index: {score}"
        severity = FindingSeverity.INFO
        if isinstance(score, int) and score < 65:
            severity = FindingSeverity.MEDIUM
        return [
            Finding(
                pack=pack_name,
                path="system",
                threat_name=f"hardening-index:{score}" if score is not None else "hardening-audit",
                severity=severity,
                message=message,
                raw_line=str(output)[:500],
            ),
        ]

    def _quarantine_findings(self, result: ScanResult) -> None:
        vault = QuarantineVault()
        for finding in result.findings:
            if finding.pack not in MALWARE_PACKS:
                continue
            if finding.path and finding.path != "system" and Path(finding.path).exists():
                try:
                    vault.add(finding.path, finding.threat_name)
                    finding.quarantined = True
                except (OSError, FileNotFoundError):
                    pass

    def cancel_job(
        self,
        job_id: str | None = None,
        *,
        force: bool = False,
    ) -> dict[str, object]:
        """Request cooperative cancel, or force-clear a zombie lock."""
        if force:
            prev = self.events.force_release_job_lock()
            if not prev:
                return {
                    "ok": False,
                    "cancelled": False,
                    "cleared": False,
                    "message": "no active job",
                    "job_id": None,
                }
            return {
                "ok": True,
                "cancelled": True,
                "cleared": True,
                "message": "job lock cleared",
                "job_id": prev,
            }
        active = self.events.active_job()
        if not active:
            return {"ok": False, "cancelled": False, "message": "no active job", "job_id": None}
        if job_id is not None and job_id != active:
            return {
                "ok": False,
                "cancelled": False,
                "message": f"active job is {active}, not {job_id}",
                "job_id": active,
            }
        if self.events.cancel_requested():
            prev = self.events.force_release_job_lock()
            return {
                "ok": True,
                "cancelled": True,
                "cleared": True,
                "message": "job lock cleared (cancel was already pending)",
                "job_id": prev,
            }
        requested = self.events.request_cancel(active)
        return {
            "ok": requested,
            "cancelled": requested,
            "message": "cancel requested" if requested else "failed to request cancel",
            "job_id": active,
        }

    def clear_job(self) -> dict[str, object]:
        """Force-clear the job lock (recovery for zombie 'scan in progress' banners)."""
        prev = self.events.force_release_job_lock()
        return {
            "ok": True,
            "cleared": prev is not None,
            "job_id": prev,
            "message": "job lock cleared" if prev else "no active job",
        }

    def job_status(self) -> dict[str, object]:
        """Return live progress for the active scan job (if any)."""
        return self.events.get_job_progress()

    def aggregate_status(self) -> dict[str, object]:
        from oyst_core.doctor_cache import doctor_all
        from oyst_core.packs.clamav import ClamAVPack
        from oyst_core.packs.clamonacc import ClamonaccPack
        from oyst_core.packs.freshclam import FreshclamPack

        packs = doctor_all()
        clam = ClamAVPack()
        fresh = FreshclamPack()
        cfg = load_config()
        clamonacc = ClamonaccPack()
        onaccess = probe_onaccess_prevention()
        prevention_enforced = bool(onaccess.get("prevention_enforced"))
        history = self.events.history(limit=1)
        last = history[0]["started_at"] if history else None
        return {
            "packs": packs,
            "clamd_running": clam.clamd_running(),
            "signature_age_hours": fresh.signature_age_hours(),
            "last_scan_at": last,
            "active_job": self.events.active_job(),
            "clamonacc_prevention_requested": cfg.clamonacc.prevention,
            "clamonacc_prevention_enforced": prevention_enforced,
            "clamonacc_onaccess": onaccess,
            "clamonacc_uses_distro_unit": clamonacc._systemd_unit() is not None,
            "fangfrisch_providers": list(cfg.fangfrisch.providers),
            "scan_backend": cfg.scan.backend,
        }
